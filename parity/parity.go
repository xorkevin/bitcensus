package parity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"slices"

	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"xorkevin.dev/bitcensus/pb/parityv0"
	"xorkevin.dev/bitcensus/reedsolomon"
	"xorkevin.dev/kerrors"
	"xorkevin.dev/klog"
)

var (
	// ErrShortHeader is returned when the provided data is short
	ErrShortHeader errShortHeader
	// ErrMalformedHeader is returned when the header is malformed
	ErrMalformedHeader errHeader
	// ErrConfig is returned when the parity config is invalid
	ErrConfig errConfig
	// ErrPacketNotFound is returned when the packet is not found in the file
	ErrPacketNotFound errPacketNotFound
	// ErrMalformedPacket is returned when the packet is malformed
	ErrMalformedPacket errPacket
	// ErrPacketNoMatch is returned when the packet does not match
	ErrPacketNoMatch errPacketNoMatch
)

type (
	errShortHeader    struct{}
	errHeader         struct{}
	errConfig         struct{}
	errPacketNotFound struct{}
	errPacket         struct{}
	errPacketNoMatch  struct{}
)

func (e errShortHeader) Error() string {
	return "Short header"
}

func (e errHeader) Error() string {
	return "Malformed header"
}

func (e errConfig) Error() string {
	return "Invalid config"
}

func (e errPacketNotFound) Error() string {
	return "Packet not found"
}

func (e errPacket) Error() string {
	return "Malformed packet"
}

func (e errPacketNoMatch) Error() string {
	return "Packet does not match"
}

type (
	PacketKind uint32
)

const (
	PacketKindIndex  PacketKind = 1
	PacketKindParity PacketKind = 3
)

type (
	CodeMatrixKind string
)

const (
	CodeMatrixKindVandermonde CodeMatrixKind = "vndr"
)

type (
	PacketHeader struct {
		Version    uint32
		headerSum  uint32
		PacketHash [HeaderHashSize]byte
		Length     uint64
		Kind       PacketKind
	}
)

const (
	PacketVersion       = 0
	MagicBytes          = "\xd5\x42\x43\x50\x0d\x0a\x1a\x04"
	HeaderHashSize      = 64
	headerVersionOffset = len(MagicBytes)
	headerSumOffset     = headerVersionOffset + 4
	headerHashOffset    = headerSumOffset + 4
	headerLengthOffset  = headerHashOffset + HeaderHashSize
	headerKindOffset    = headerLengthOffset + 8
	HeaderSize          = headerKindOffset + 4
	maxPacketLength     = 1 << 28 // 256MiB
)

func (h *PacketHeader) MarshalBinary() ([]byte, error) {
	res := make([]byte, HeaderSize)
	copy(res, []byte(MagicBytes))
	binary.BigEndian.PutUint32(res[headerVersionOffset:], h.Version)
	binary.BigEndian.PutUint32(res[headerSumOffset:], h.Sum())
	copy(res[headerHashOffset:], h.PacketHash[:])
	binary.BigEndian.PutUint64(res[headerLengthOffset:], h.Length)
	binary.BigEndian.PutUint32(res[headerKindOffset:], uint32(h.Kind))
	return res, nil
}

func (h *PacketHeader) UnmarshalBinary(data []byte) error {
	if len(data) < headerSumOffset {
		return kerrors.WithKind(nil, ErrShortHeader, "Short header")
	}
	if !bytes.Equal(data[:headerVersionOffset], []byte(MagicBytes)) {
		return kerrors.WithKind(nil, ErrMalformedHeader, "Invalid magic bytes")
	}
	{
		v := binary.BigEndian.Uint32(data[headerVersionOffset:])
		if v != PacketVersion {
			return kerrors.WithKind(nil, ErrMalformedHeader, "Invalid version")
		}
		h.Version = v
	}
	if len(data) < HeaderSize {
		return kerrors.WithKind(nil, ErrShortHeader, "Short header")
	}
	h.headerSum = binary.BigEndian.Uint32(data[headerSumOffset:])
	copy(h.PacketHash[:], data[headerHashOffset:])
	h.Length = binary.BigEndian.Uint64(data[headerLengthOffset:])
	h.Kind = PacketKind(binary.BigEndian.Uint32(data[headerKindOffset:]))
	return nil
}

func (h *PacketHeader) Sum() uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	var n [8]byte
	binary.BigEndian.PutUint32(n[:], h.Version)
	s := crc32.Checksum(n[:4], t)
	s = crc32.Update(s, t, h.PacketHash[:])
	binary.BigEndian.PutUint64(n[:], h.Length)
	s = crc32.Update(s, t, n[:])
	binary.BigEndian.PutUint32(n[:], uint32(h.Kind))
	s = crc32.Update(s, t, n[:4])
	return s
}

func (h *PacketHeader) Verify() error {
	if h.Sum() != h.headerSum {
		return kerrors.WithKind(nil, ErrMalformedHeader, "Invalid checksum")
	}
	return nil
}

func (h *PacketHeader) SetSum() {
	h.headerSum = h.Sum()
}

const (
	hashBlockSize = 128
)

var (
	hashBlockZeroBuf = [hashBlockSize]byte{}
	emptyHeaderHash  = [HeaderHashSize]byte{}
)

func calcPacketHash(header PacketHeader, data []byte) ([HeaderHashSize]byte, error) {
	h, err := blake2b.New512(nil)
	if err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed to create packet hash")
	}
	if n, err := h.Write(data); err != nil {
		// should not happen as specified by [hash.Hash]
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing to packet hash")
	} else if n != len(data) {
		// should never happen
		return emptyHeaderHash, kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	if n := len(data) % hashBlockSize; n != 0 {
		// pad length to hashBlockSize bytes
		l := hashBlockSize - n
		if k, err := h.Write(hashBlockZeroBuf[:l]); err != nil {
			// should not happen as specified by [hash.Hash]
			return emptyHeaderHash, kerrors.WithMsg(err, "Failed to write padding to packet hash")
		} else if k != int(l) {
			// should never happen
			return emptyHeaderHash, kerrors.WithMsg(io.ErrShortWrite, "Short write")
		}
	}
	var trailer [16]byte
	binary.BigEndian.PutUint32(trailer[:], header.Version)
	binary.LittleEndian.PutUint64(trailer[4:], uint64(len(data)))
	binary.BigEndian.PutUint32(trailer[12:], uint32(header.Kind))
	if n, err := h.Write(trailer[:]); err != nil {
		// should not happen as specified by [hash.Hash]
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed to write trailer to packet hash")
	} else if n != 16 {
		return emptyHeaderHash, kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	var packetHash [HeaderHashSize]byte
	copy(packetHash[:], h.Sum(nil))
	return packetHash, nil
}

func writePacket(w io.Writer, kind PacketKind, data []byte) ([HeaderHashSize]byte, error) {
	header := PacketHeader{
		Version: PacketVersion,
		Length:  uint64(len(data)),
		Kind:    kind,
	}
	var err error
	header.PacketHash, err = calcPacketHash(header, data)
	if err != nil {
		return emptyHeaderHash, err
	}
	headerBytes, err := header.MarshalBinary()
	if err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed to marshal packet header")
	}
	if n, err := w.Write(headerBytes); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed to write packet header")
	} else if n != len(headerBytes) {
		// should never happen
		return emptyHeaderHash, kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	if n, err := w.Write(data); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing packet body")
	} else if n != len(data) {
		// should never happen
		return emptyHeaderHash, kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	return header.PacketHash, nil
}

type (
	streamReader struct {
		r           io.ReadSeeker
		buf         byteBuffer
		pos         int64
		maxPos      int64
		indexCache  map[[HeaderHashSize]byte][]cacheCandidate
		parityCache map[[HeaderHashSize]byte][]cacheCandidate
	}

	cacheCandidate struct {
		pos     int64
		invalid bool
	}
)

func newStreamReader(r io.ReadSeeker, buf []byte) *streamReader {
	return &streamReader{
		r:           r,
		buf:         byteBuffer{buf: buf, read: 0, write: 0},
		pos:         0,
		maxPos:      0,
		indexCache:  map[[HeaderHashSize]byte][]cacheCandidate{},
		parityCache: map[[HeaderHashSize]byte][]cacheCandidate{},
	}
}

func (r *streamReader) Reset(reader io.ReadSeeker) {
	r.buf.Reset()
	r.pos = 0
	r.maxPos = 0
	clear(r.indexCache)
	clear(r.parityCache)
	r.r = reader
}

func (r *streamReader) GetPacket(match PacketMatch) ([]byte, int64, error) {
	if match.Hash != emptyHeaderHash {
		var candidates []cacheCandidate
		switch match.Kind {
		case PacketKindIndex:
			candidates = r.indexCache[match.Hash]
		case PacketKindParity:
			candidates = r.parityCache[match.Hash]
		}
		for n, i := range candidates {
			if i.invalid {
				continue
			}
			if err := r.seek(i.pos); err != nil {
				return nil, 0, kerrors.WithMsg(err, "Failed seeking to parity file")
			}
			_, body, err := r.readPacket(match)
			if err != nil {
				if errors.Is(err, ErrPacketNoMatch) || errors.Is(err, ErrMalformedPacket) {
					candidates[n].invalid = true
					continue
				}
				return nil, 0, err
			}
			return body, i.pos, nil
		}
	}
	return r.linearScanPacket(match)
}

func (r *streamReader) cachePacket(header PacketHeader, pos int64) {
	if header.Kind == PacketKindIndex {
		r.indexCache[header.PacketHash] = append(r.indexCache[header.PacketHash], cacheCandidate{
			pos:     pos,
			invalid: false,
		})
	} else if header.Kind == PacketKindParity {
		r.parityCache[header.PacketHash] = append(r.parityCache[header.PacketHash], cacheCandidate{
			pos:     pos,
			invalid: false,
		})
	}
}

func (r *streamReader) linearScanPacket(match PacketMatch) ([]byte, int64, error) {
	if err := r.seek(r.maxPos); err != nil {
		return nil, 0, kerrors.WithMsg(err, "Failed seeking to parity file")
	}
	for {
		var header PacketHeader
		var body []byte
		var err error
		header, body, err = r.readPacket(match)
		if err != nil {
			if errors.Is(err, ErrPacketNoMatch) {
				r.cachePacket(header, r.pos)
			} else if errors.Is(err, ErrMalformedPacket) {
			} else {
				return nil, 0, err
			}

			// advance only one byte to prevent finding same magic bytes on current
			// pos if one exists
			if err := r.advance(1); err != nil {
				return nil, 0, err
			}
			if idx := bytes.Index(r.buf.Bytes(), []byte(MagicBytes)); idx >= 0 {
				if err := r.advance(idx); err != nil {
					return nil, 0, err
				}
				continue
			}
			// keep an overlap amount of bytes because they could be a prefix of a
			// magic bytes completed by the next buffer read
			const overlap = len(MagicBytes) - 1
			// buf read at least full header
			delta := r.buf.Len() - overlap
			if err := r.advance(delta); err != nil {
				return nil, 0, err
			}
			continue
		}
		pos := r.pos
		r.cachePacket(header, pos)
		// may only advance length of packet in this scenario because packet has
		// been verified
		if err := r.advance(HeaderSize + int(header.Length)); err != nil {
			return body, 0, err
		}
		return body, pos, nil
	}
}

// advance advances the buffer and file position
//
// may only be called from linearScanPacket
func (r *streamReader) advance(delta int) error {
	if err := r.buf.Advance(delta); err != nil {
		return err
	}
	r.pos += int64(delta)
	r.maxPos = r.pos
	return nil
}

// seek seeks to a particular position in the file
func (r *streamReader) seek(pos int64) error {
	r.buf.Reset()
	if _, err := r.r.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	r.pos = pos
	return nil
}

type (
	PacketMatch struct {
		Kind   PacketKind
		Hash   [HeaderHashSize]byte
		Length uint64
	}
)

func (r *streamReader) readPacket(match PacketMatch) (PacketHeader, []byte, error) {
	if r.buf.Cap() < HeaderSize {
		// allocate more space for abnormally small buffers for performance
		r.buf.Realloc(1024 * 1024)
	}

	if err := r.buf.Fill(r.r, HeaderSize); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return PacketHeader{}, nil, kerrors.WithKind(err, ErrPacketNotFound, "Packet not found")
		}
		return PacketHeader{}, nil, kerrors.WithMsg(err, "Failed to read parity file")
	}

	b := r.buf.Bytes()
	var header PacketHeader
	if err := header.UnmarshalBinary(b); err != nil {
		return PacketHeader{}, nil, kerrors.WithKind(err, ErrMalformedPacket, "Invalid packet header")
	}
	if err := header.Verify(); err != nil {
		return PacketHeader{}, nil, kerrors.WithKind(err, ErrMalformedPacket, "Invalid packet header")
	}
	if header.Length > maxPacketLength {
		return PacketHeader{}, nil, kerrors.WithKind(nil, ErrMalformedPacket, "Packet exceeds max size")
	}

	if header.Kind != match.Kind {
		return header, nil, kerrors.WithKind(nil, ErrPacketNoMatch, "Packet kind does not match")
	}
	if match.Hash != emptyHeaderHash && header.PacketHash != match.Hash {
		return header, nil, kerrors.WithKind(nil, ErrPacketNoMatch, "Packet hash does not match")
	}
	if match.Length != 0 && header.Length != match.Length {
		return header, nil, kerrors.WithKind(nil, ErrPacketNoMatch, "Packet length does not match")
	}

	packetSize := HeaderSize + int(header.Length)
	if err := r.buf.Fill(r.r, packetSize); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// do not return error since EOF for a partial large packet does not
			// imply that smaller packets do not exist
			return header, nil, kerrors.WithKind(nil, ErrMalformedPacket, "Packet length exceeds end of file")
		}
		return PacketHeader{}, nil, kerrors.WithMsg(err, "Failed to read parity file")
	}

	b = r.buf.Bytes()[HeaderSize:packetSize]
	packetHash, err := calcPacketHash(header, b)
	if err != nil {
		return PacketHeader{}, nil, err
	}
	if packetHash != header.PacketHash {
		return header, nil, kerrors.WithKind(nil, ErrMalformedPacket, "Packet body corrupted")
	}
	return header, b, nil
}

type (
	byteBuffer struct {
		buf   []byte
		read  int
		write int
	}
)

func (b *byteBuffer) Reset() {
	b.read = 0
	b.write = 0
}

func (b *byteBuffer) Bytes() []byte {
	return b.buf[b.read:b.write]
}

func (b *byteBuffer) Cap() int {
	return len(b.buf)
}

func (b *byteBuffer) Len() int {
	return b.write - b.read
}

func (b *byteBuffer) Remaining() int {
	return len(b.buf) - b.write
}

func (b *byteBuffer) Realloc(size int) {
	if len(b.buf) >= size {
		return
	}
	next := make([]byte, size)
	b.write = copy(next, b.buf[b.read:b.write])
	b.read = 0
	b.buf = next
}

func (b *byteBuffer) Compact() {
	if b.read == 0 {
		return
	}
	b.write = copy(b.buf, b.buf[b.read:b.write])
	b.read = 0
}

func (b *byteBuffer) EnsureLen(size int) {
	// ensure the buffer has enough space
	b.Realloc(size)

	req := size - b.Len()
	if req <= 0 {
		// requested data already exists
		return
	}
	if b.Remaining() >= req {
		// remaining buffer can satisfy request
		return
	}
	// compact since remaining buffer cannot satisfy request
	b.Compact()
}

func (b *byteBuffer) Fill(r io.Reader, size int) error {
	// ensure remaining buffer can satisfy request
	b.EnsureLen(size)
	req := size - b.Len()
	n, err := io.ReadAtLeast(r, b.buf[b.write:], req)
	b.write += n
	return err
}

func (b *byteBuffer) Advance(delta int) error {
	if delta < 0 {
		return kerrors.WithMsg(nil, "Read pointer may not advance backward")
	}
	if delta > b.Len() {
		return kerrors.WithMsg(nil, "Read pointer advance exceeds written data")
	}
	b.read += delta
	return nil
}

type (
	bitSet struct {
		bits     []uint64
		size     int
		capacity int
	}
)

func newBitSet(size int) *bitSet {
	return &bitSet{
		bits:     make([]uint64, (size+63)/64),
		size:     0,
		capacity: size,
	}
}

func (s *bitSet) Size() int {
	return s.size
}

func (s *bitSet) Cap() int {
	return s.capacity
}

func (s *bitSet) Clear() {
	clear(s.bits)
	s.size = 0
}

func (s *bitSet) Contains(i int) bool {
	a := i / 64
	b := i % 64
	mask := uint64(1) << b
	return s.bits[a]&mask != 0
}

func (s *bitSet) Add(i int) {
	a := i / 64
	b := i % 64
	mask := uint64(1) << b
	if s.bits[a]&mask == 0 {
		s.bits[a] |= mask
		s.size++
	}
}

func (s *bitSet) Rm(i int) {
	a := i / 64
	b := i % 64
	mask := uint64(1) << b
	if s.bits[a]&mask != 0 {
		s.bits[a] &= ^mask
		s.size--
	}
}

type (
	ShardConfig struct {
		BlockSize        uint64
		ShardCount       uint64
		ParityShardCount uint64
	}

	blockLayout struct {
		FileSize           uint64
		BlockSize          uint64
		NumBlocks          uint64
		LastBlockSize      uint64
		ShardCount         uint64
		ShardStride        uint64
		NumLastShardBlocks uint64
		ParityShardCount   uint64
		NumParityBlocks    uint64
	}
)

func partitionBlocks(fileSize uint64, cfg ShardConfig) (*blockLayout, error) {
	layout := blockLayout{
		FileSize:         fileSize,
		BlockSize:        cfg.BlockSize,
		ShardCount:       cfg.ShardCount,
		ParityShardCount: cfg.ParityShardCount,
	}
	if layout.ShardCount+layout.ParityShardCount > 255 {
		return nil, kerrors.WithKind(nil, ErrConfig, "Shard counts may not exceed 255")
	}
	layout.BlockSize = min(layout.BlockSize, layout.FileSize)
	if layout.FileSize == 0 {
		layout.ShardCount = 0
		return &layout, nil
	}
	if layout.BlockSize == 0 {
		return nil, kerrors.WithKind(nil, ErrConfig, "Invalid block size")
	}
	if layout.ShardCount == 0 {
		return nil, kerrors.WithKind(nil, ErrConfig, "Invalid shard count")
	}
	layout.NumBlocks = (layout.FileSize + layout.BlockSize - 1) / layout.BlockSize
	layout.LastBlockSize = layout.FileSize - layout.BlockSize*(layout.NumBlocks-1)
	layout.ShardStride = (layout.NumBlocks + layout.ShardCount - 1) / layout.ShardCount
	// shard count must be recomputed since shard stride may cause some shards to
	// be empty
	layout.ShardCount = (layout.NumBlocks + layout.ShardStride - 1) / layout.ShardStride
	layout.NumLastShardBlocks = layout.NumBlocks - layout.ShardStride*(layout.ShardCount-1)
	layout.NumParityBlocks = layout.ShardStride * layout.ParityShardCount
	return &layout, nil
}

func (l blockLayout) isLastShardEmptyBlock(shardIdx int, stripeIdx int) bool {
	return stripeIdx >= int(l.NumLastShardBlocks) && shardIdx == int(l.ShardCount-1)
}

func (l blockLayout) calcBlockIdx(shardIdx int, stripeIdx int) int {
	return int(l.ShardStride)*shardIdx + stripeIdx
}

func (l blockLayout) calcDataBlockOffset(blockIdx int) int64 {
	return int64(l.BlockSize) * int64(blockIdx)
}

func (l blockLayout) isLastDataBlock(blockIdx int) bool {
	return blockIdx == int(l.NumBlocks-1)
}

func initIndexBlocks(numBlocks, parityBlocks uint64) *parityv0.BlockSet {
	blocks := make([]*parityv0.Block, numBlocks+parityBlocks)
	blockHashes := make([][blake2b.Size]byte, numBlocks+parityBlocks)
	var counter [8]byte
	for i := range blocks {
		binary.BigEndian.PutUint64(counter[:], uint64(i))
		blockHashes[i] = blake2b.Sum512(counter[:])
		blocks[i] = &parityv0.Block{
			Hash: blockHashes[i][:],
		}
	}
	return &parityv0.BlockSet{
		Input:  blocks[:numBlocks],
		Parity: blocks[numBlocks:],
	}
}

func hashDataBlocks(indexPacket *parityv0.IndexPacket, data io.Reader, blockSize, lastBlockSize uint64) ([HeaderHashSize]byte, error) {
	fileHasher, err := blake2b.New512(nil)
	if err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed to create file hasher")
	}
	if blockSize > 0 {
		buf := make([]byte, blockSize)
		for blockIdx := range indexPacket.BlockSet.Input {
			clear(buf)
			b := buf
			if blockIdx == len(indexPacket.BlockSet.Input)-1 {
				b = b[:lastBlockSize]
			}
			if _, err := io.ReadFull(data, b); err != nil {
				return emptyHeaderHash, kerrors.WithMsg(err, "Failed reading input file")
			}
			if _, err := fileHasher.Write(b); err != nil {
				return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing to hasher")
			}
			h := blake2b.Sum512(b)
			copy(indexPacket.BlockSet.Input[blockIdx].Hash, h[:])
		}
	}
	var fileHash [HeaderHashSize]byte
	copy(fileHash[:], fileHasher.Sum(nil))
	indexPacket.InputFile.Hash = fileHash[:]
	return fileHash, nil
}

type (
	parityFilePacketSizes struct {
		indexBody uint64
		index     uint64
		parity    uint64
		shard     uint64
		fileBody  uint64
		file      uint64
	}
)

func calcPacketSizes(indexBody uint64, layout blockLayout) parityFilePacketSizes {
	index := uint64(HeaderSize) + indexBody
	parity := uint64(HeaderSize) + layout.BlockSize
	shard := index + parity*layout.ShardStride
	fileBody := shard * layout.ParityShardCount
	return parityFilePacketSizes{
		indexBody: indexBody,
		index:     index,
		parity:    parity,
		shard:     shard,
		fileBody:  fileBody,
		file:      fileBody + index,
	}
}

func (p parityFilePacketSizes) calcParityPacketOffset(shardIdx int, stripeIdx int) int64 {
	return int64(p.shard)*int64(shardIdx) + int64(p.index) + int64(p.parity)*int64(stripeIdx)
}

func allocBlockBuffers(blockSize, count uint64) ([][]byte, []byte) {
	buf := make([]byte, blockSize*count)
	blocks := make([][]byte, count)
	for i := range blocks {
		start := int(blockSize) * i
		blocks[i] = buf[start : start+int(blockSize)]
	}
	return blocks, buf
}

type (
	WriteSeekTruncater interface {
		io.WriteSeeker
		Truncate(size int64) error
	}
)

func WriteParityFile(w WriteSeekTruncater, data io.ReadSeeker, shardCfg ShardConfig) ([HeaderHashSize]byte, [HeaderHashSize]byte, error) {
	fileSize, err := data.Seek(0, io.SeekEnd)
	if err != nil {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking to end of input file")
	}
	if _, err := data.Seek(0, io.SeekStart); err != nil {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking to beginning of input file")
	}

	layout, err := partitionBlocks(uint64(fileSize), shardCfg)
	if err != nil {
		return emptyHeaderHash, emptyHeaderHash, err
	}

	indexPacket := parityv0.IndexPacket{
		InputFile: &parityv0.InputFile{
			Size: layout.FileSize,
		},
		ShardConfig: &parityv0.ShardConfig{
			BlockSize:   layout.BlockSize,
			Count:       layout.ShardCount,
			ParityCount: layout.ParityShardCount,
		},
	}
	if layout.ShardCount > 0 && layout.ParityShardCount > 0 {
		indexPacket.ShardConfig.CodeMatrixConfig = &parityv0.CodeMatrixConfig{
			Kind: string(CodeMatrixKindVandermonde),
		}
	}
	if layout.NumBlocks > 0 {
		indexPacket.BlockSet = initIndexBlocks(layout.NumBlocks, layout.NumParityBlocks)
	}

	fileHash, err := hashDataBlocks(&indexPacket, data, layout.BlockSize, layout.LastBlockSize)
	if err != nil {
		return emptyHeaderHash, emptyHeaderHash, err
	}

	packetSizes := calcPacketSizes(uint64(proto.Size(&indexPacket)), *layout)
	if err := w.Truncate(int64(packetSizes.file)); err != nil {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed resizing parity file")
	}

	if layout.BlockSize > 0 {
		var enc *reedsolomon.Matrix
		if layout.ParityShardCount > 0 {
			var err error
			enc, err = reedsolomon.NewVandermondeEncoder(int(layout.ShardCount), int(layout.ParityShardCount))
			if err != nil {
				return emptyHeaderHash, emptyHeaderHash, kerrors.WithKind(err, ErrConfig, "Invalid parity config")
			}
		}

		allBlocks, buf := allocBlockBuffers(layout.BlockSize, layout.ShardCount+layout.ParityShardCount)
		dataBlocks := allBlocks[:layout.ShardCount]
		parityBlocks := allBlocks[layout.ShardCount:]
		for stripeIdx := range int(layout.ShardStride) {
			// clear buffer before reading
			clear(buf)

			for shardIdx, i := range dataBlocks {
				if layout.isLastShardEmptyBlock(shardIdx, stripeIdx) {
					break
				}
				blockIdx := layout.calcBlockIdx(shardIdx, stripeIdx)
				if _, err := data.Seek(layout.calcDataBlockOffset(blockIdx), io.SeekStart); err != nil {
					return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking input file")
				}
				b := i
				if layout.isLastDataBlock(blockIdx) {
					b = i[:layout.LastBlockSize]
				}
				if _, err := io.ReadFull(data, b); err != nil {
					return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed reading input file")
				}
				h := blake2b.Sum512(b)
				if !bytes.Equal(indexPacket.BlockSet.Input[blockIdx].Hash, h[:]) {
					return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "File changed during reading")
				}
			}

			if enc != nil {
				if err := enc.Encode(dataBlocks, parityBlocks); err != nil {
					return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed encoding parity blocks")
				}
			}

			for shardIdx, i := range parityBlocks {
				if _, err := w.Seek(packetSizes.calcParityPacketOffset(shardIdx, stripeIdx), io.SeekStart); err != nil {
					return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
				}
				h, err := writePacket(w, PacketKindParity, i)
				if err != nil {
					return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed writing parity packet")
				}
				copy(indexPacket.BlockSet.Parity[layout.calcBlockIdx(shardIdx, stripeIdx)].Hash, h[:])
			}
		}
	}

	indexPacketBytes, err := proto.Marshal(&indexPacket)
	if err != nil {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed marshalling index packet")
	}
	if len(indexPacketBytes) != int(packetSizes.indexBody) {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Inconsistent marshalled index packet size")
	}
	for i := range layout.ParityShardCount {
		if _, err := w.Seek(int64(packetSizes.shard)*int64(i), io.SeekStart); err != nil {
			return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
		}
		if _, err := writePacket(w, PacketKindIndex, indexPacketBytes); err != nil {
			return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed writing index packet")
		}
	}
	if _, err := w.Seek(int64(packetSizes.fileBody), io.SeekStart); err != nil {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
	}
	indexPacketHeaderHash, err := writePacket(w, PacketKindIndex, indexPacketBytes)
	if err != nil {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed writing index packet")
	}
	return fileHash, indexPacketHeaderHash, nil
}

func RepairFile(ctx context.Context, log klog.Logger, data, parity io.ReadWriteSeeker, fileHash [HeaderHashSize]byte) error {
	l := klog.NewLevelLogger(log)

	reader := newStreamReader(parity, nil)

	var indexBody []byte
	if b, _, err := reader.GetPacket(PacketMatch{Kind: PacketKindIndex}); err != nil {
		return kerrors.WithMsg(err, "Failed to find index packet")
	} else {
		indexBody = slices.Clone(b)
	}
	var indexPacket parityv0.IndexPacket
	if err := proto.Unmarshal(indexBody, &indexPacket); err != nil {
		return kerrors.WithMsg(err, "Failed unmarshalling index packet")
	}

	// perform heuristic check on whether the parity and the data file match
	if !bytes.Equal(fileHash[:], indexPacket.GetInputFile().GetHash()) {
		return kerrors.WithMsg(nil, "Mismatched file hash")
	}
	fileSize := indexPacket.GetInputFile().GetSize()
	if dataFileSize, err := data.Seek(0, io.SeekEnd); err != nil {
		return kerrors.WithMsg(err, "Failed seeking to end of data file")
	} else if uint64(dataFileSize) != fileSize {
		return kerrors.WithMsg(nil, "Mismatched file size")
	}
	if _, err := data.Seek(0, io.SeekStart); err != nil {
		return kerrors.WithMsg(err, "Failed seeking to beginning of data file")
	}

	shardCfg := ShardConfig{
		BlockSize:        indexPacket.GetShardConfig().GetBlockSize(),
		ShardCount:       indexPacket.GetShardConfig().GetCount(),
		ParityShardCount: indexPacket.GetShardConfig().GetParityCount(),
	}
	layout, err := partitionBlocks(fileSize, shardCfg)
	if err != nil {
		return kerrors.WithMsg(err, "Index packet has invalid shard config")
	}
	if layout.BlockSize != shardCfg.BlockSize {
		return kerrors.WithMsg(nil, "Index packet block size mismatch")
	}
	if layout.ShardCount != shardCfg.ShardCount {
		return kerrors.WithMsg(nil, "Index packet shard count mismatch")
	}
	if layout.ParityShardCount != shardCfg.ParityShardCount {
		return kerrors.WithMsg(nil, "Index packet parity shard count mismatch")
	}

	packetSizes := calcPacketSizes(uint64(len(indexBody)), *layout)

	var failedRepair []int

	if layout.BlockSize > 0 {
		var enc *reedsolomon.Matrix
		if layout.ParityShardCount > 0 {
			if indexPacket.GetShardConfig().GetCodeMatrixConfig().GetKind() != string(CodeMatrixKindVandermonde) {
				return kerrors.WithMsg(nil, "Invalid code matrix kind")
			}
			var err error
			enc, err = reedsolomon.NewVandermondeEncoder(int(layout.ShardCount), int(layout.ParityShardCount))
			if err != nil {
				return kerrors.WithKind(err, ErrConfig, "Invalid parity config")
			}
		}

		validParityStripes := newBitSet(int(layout.ShardStride))
		validParityBlocks := newBitSet(int(layout.NumParityBlocks))

		allBlocks, buf := allocBlockBuffers(layout.BlockSize, layout.ShardCount+layout.ParityShardCount)
		invalidDataShards := newBitSet(int(layout.ShardCount))
		for stripeIdx := range int(layout.ShardStride) {
			// clear buffer before reading
			clear(buf)
			invalidDataShards.Clear()

			dataBlocks := allBlocks[:layout.ShardCount]
			parityBlocks := allBlocks[layout.ShardCount:]

			for shardIdx, i := range dataBlocks {
				if layout.isLastShardEmptyBlock(shardIdx, stripeIdx) {
					break
				}
				blockIdx := layout.calcBlockIdx(shardIdx, stripeIdx)
				if _, err := data.Seek(int64(layout.BlockSize)*int64(blockIdx), io.SeekStart); err != nil {
					return kerrors.WithMsg(err, "Failed seeking data file")
				}
				b := i
				if blockIdx == len(indexPacket.BlockSet.Input)-1 {
					b = i[:layout.LastBlockSize]
				}
				if _, err := io.ReadFull(data, b); err != nil {
					return kerrors.WithMsg(err, "Failed reading data file")
				}
				h := blake2b.Sum512(b)
				if !bytes.Equal(indexPacket.BlockSet.Input[blockIdx].Hash, h[:]) {
					// mark data block for repair
					invalidDataShards.Add(shardIdx)
					dataBlocks[shardIdx] = dataBlocks[shardIdx][:0]

					l.Warn(ctx, "Block corrupted",
						klog.AString("kind", "data"),
						klog.AInt("idx", blockIdx),
						klog.AInt("shard", shardIdx),
						klog.AInt("stripe", stripeIdx),
					)
				} else {
					l.Debug(ctx, "Block ok",
						klog.AString("kind", "data"),
						klog.AInt("idx", blockIdx),
						klog.AInt("shard", shardIdx),
						klog.AInt("stripe", stripeIdx),
					)
				}
			}

			hasCorruptedData := invalidDataShards.Size() > 0
			if hasCorruptedData {
				l.Warn(ctx, "Stripe has corrupted blocks",
					klog.AString("kind", "data"),
					klog.AInt("stripe", stripeIdx),
				)
			} else {
				l.Debug(ctx, "Stripe blocks ok",
					klog.AString("kind", "data"),
					klog.AInt("stripe", stripeIdx),
				)
			}

			okParityCount := 0
			for shardIdx, i := range parityBlocks {
				var h [HeaderHashSize]byte
				blockIdx := layout.calcBlockIdx(shardIdx, stripeIdx)
				if copy(h[:], indexPacket.GetBlockSet().GetParity()[blockIdx].GetHash()) != HeaderHashSize {
					parityBlocks[shardIdx] = parityBlocks[shardIdx][:0]

					l.Warn(ctx, "Packet hash is wrong size",
						klog.AString("kind", "parity"),
						klog.AInt("idx", blockIdx),
						klog.AInt("shard", shardIdx),
						klog.AInt("stripe", stripeIdx),
					)
					continue
				}
				parityBody, parityPos, err := reader.GetPacket(PacketMatch{Kind: PacketKindParity, Hash: h, Length: layout.BlockSize})
				if err != nil {
					parityBlocks[shardIdx] = parityBlocks[shardIdx][:0]

					l.Warn(ctx, "Block corrupted",
						klog.AString("kind", "parity"),
						klog.AInt("idx", blockIdx),
						klog.AInt("shard", shardIdx),
						klog.AInt("stripe", stripeIdx),
					)
					continue
				}
				copy(i, parityBody)
				if parityPos == packetSizes.calcParityPacketOffset(shardIdx, stripeIdx) {
					validParityBlocks.Add(blockIdx)
					okParityCount++
				} else {
					l.Warn(ctx, "Block misplaced",
						klog.AString("kind", "parity"),
						klog.AInt("idx", blockIdx),
						klog.AInt("shard", shardIdx),
						klog.AInt("stripe", stripeIdx),
					)
				}
			}

			if okParityCount == len(parityBlocks) {
				validParityStripes.Add(stripeIdx)

				l.Debug(ctx, "Stripe blocks ok",
					klog.AString("kind", "parity"),
					klog.AInt("stripe", stripeIdx),
				)
			} else {
				l.Warn(ctx, "Stripe has corrupted blocks",
					klog.AString("kind", "parity"),
					klog.AInt("stripe", stripeIdx),
				)
			}

			if hasCorruptedData {
				if enc == nil {
					failedRepair = append(failedRepair, stripeIdx)

					l.Error(ctx, "Unable to repair data blocks",
						klog.AInt("stripe", stripeIdx),
						klog.AInt("count.data", len(dataBlocks)-invalidDataShards.Size()),
						klog.AInt("count.parity", okParityCount),
					)
				} else {
					if err := enc.ReconstructData(dataBlocks, parityBlocks); err != nil {
						failedRepair = append(failedRepair, stripeIdx)

						l.Err(ctx, kerrors.WithMsg(err, "Unable to repair data blocks"),
							klog.AInt("stripe", stripeIdx),
							klog.AInt("count.data", len(dataBlocks)-invalidDataShards.Size()),
							klog.AInt("count.parity", okParityCount),
						)
					}
				}
			}

			// TODO repair data blocks
		}
	}

	// TODO repair parity file

	return nil
}
