package parity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"slices"
	"time"

	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"xorkevin.dev/bitcensus/pb/parityv0"
	"xorkevin.dev/bitcensus/reedsolomon"
	"xorkevin.dev/bitcensus/util/bytefmt"
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
	// ErrFailRepair is returned when not enough data exists to repair
	ErrFailRepair errFailRepair
	// ErrFileNoMatch is returned when the file does not match
	ErrFileNoMatch errFileNoMatch
)

type (
	errShortHeader    struct{}
	errHeader         struct{}
	errConfig         struct{}
	errPacketNotFound struct{}
	errPacket         struct{}
	errPacketNoMatch  struct{}
	errFailRepair     struct{}
	errFileNoMatch    struct{}
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

func (e errFailRepair) Error() string {
	return "Failed to repair file"
}

func (e errFileNoMatch) Error() string {
	return "File does not match"
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
	Hash [HeaderHashSize]byte

	PacketHeader struct {
		Version    uint32
		headerSum  uint32
		PacketHash Hash
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
	if !bytes.Equal([]byte(MagicBytes), data[:headerVersionOffset]) {
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
	emptyHeaderHash  = Hash{}
)

func calcPacketHash(header PacketHeader, data []byte) (Hash, error) {
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
	var packetHash Hash
	copy(packetHash[:], h.Sum(nil))
	return packetHash, nil
}

func writePacket(w io.Writer, kind PacketKind, data []byte) (Hash, error) {
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
		indexCache  map[Hash][]cacheCandidate
		parityCache map[Hash][]cacheCandidate
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
		indexCache:  map[Hash][]cacheCandidate{},
		parityCache: map[Hash][]cacheCandidate{},
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
				return nil, 0, kerrors.WithMsg(err, "Failed seeking parity file")
			}
			_, body, err := r.readPacket(match)
			if err != nil {
				if errors.Is(err, ErrPacketNoMatch) || errors.Is(err, ErrMalformedPacket) || errors.Is(err, ErrPacketNotFound) {
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

func (r *streamReader) ValidatePacket(match PacketMatch, pos int64) (bool, error) {
	if err := r.seek(pos); err != nil {
		return false, kerrors.WithMsg(err, "Failed seeking parity file")
	}
	if _, _, err := r.readPacket(match); err != nil {
		if errors.Is(err, ErrPacketNoMatch) || errors.Is(err, ErrMalformedPacket) || errors.Is(err, ErrPacketNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
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
		return nil, 0, kerrors.WithMsg(err, "Failed seeking parity file")
	}
	for {
		pos := r.pos
		var header PacketHeader
		var body []byte
		var err error
		header, body, err = r.readPacket(match)
		if err != nil {
			if errors.Is(err, ErrPacketNoMatch) {
				r.cachePacket(header, pos)
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
		Hash   Hash
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

func (s *bitSet) Has(i int) bool {
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

func (l blockLayout) calcStripeDataBlocks(stripeIdx int) int {
	if stripeIdx >= int(l.NumLastShardBlocks) {
		return int(l.ShardCount) - 1
	}
	return int(l.ShardCount)
}

func (l blockLayout) isLastShardEmptyBlock(shardIdx int, stripeIdx int) bool {
	return stripeIdx >= int(l.NumLastShardBlocks) && shardIdx == int(l.ShardCount)-1
}

func (l blockLayout) calcBlockIdx(shardIdx int, stripeIdx int) int {
	return int(l.ShardStride)*shardIdx + stripeIdx
}

func (l blockLayout) calcDataBlockOffset(blockIdx int) int64 {
	return int64(l.BlockSize) * int64(blockIdx)
}

func (l blockLayout) isLastDataBlock(blockIdx int) bool {
	return blockIdx == int(l.NumBlocks)-1
}

func initIndexBlocks(numBlocks, parityBlocks uint64) *parityv0.BlockSet {
	blocks := make([]*parityv0.Block, numBlocks+parityBlocks)
	blockHashes := make([][blake2b.Size]byte, numBlocks+parityBlocks)
	var counter [8]byte
	for i := range blocks {
		binary.BigEndian.PutUint64(counter[:], uint64(i))
		blockHashes[i] = blake2b.Sum512(counter[:])
		blocks[i] = parityv0.Block_builder{
			Hash: blockHashes[i][:],
		}.Build()
	}
	return parityv0.BlockSet_builder{
		Input:  blocks[:numBlocks],
		Parity: blocks[numBlocks:],
	}.Build()
}

func hashDataBlocks(indexPacket *parityv0.IndexPacket, data io.Reader, layout blockLayout) (Hash, error) {
	fileHasher, err := blake2b.New512(nil)
	if err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed to create file hasher")
	}
	if layout.BlockSize > 0 {
		buf := make([]byte, layout.BlockSize)
		for blockIdx := range indexPacket.GetBlockSet().GetInput() {
			clear(buf)
			b := buf
			if layout.isLastDataBlock(blockIdx) {
				b = b[:layout.LastBlockSize]
			}
			if _, err := io.ReadFull(data, b); err != nil {
				return emptyHeaderHash, kerrors.WithMsg(err, "Failed reading input file")
			}
			if _, err := fileHasher.Write(b); err != nil {
				return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing to hasher")
			}
			h := blake2b.Sum512(b)
			copy(indexPacket.GetBlockSet().GetInput()[blockIdx].GetHash(), h[:])
		}
	}
	var fileHash Hash
	copy(fileHash[:], fileHasher.Sum(nil))
	indexPacket.GetInputFile().SetHash(fileHash[:])
	return fileHash, nil
}

type (
	parityFilePacketSizes struct {
		parityShardCount uint64
		indexBody        uint64
		index            uint64
		parity           uint64
		shard            uint64
		fileBody         uint64
		file             uint64
	}
)

func calcPacketSizes(indexBody uint64, layout blockLayout) parityFilePacketSizes {
	index := uint64(HeaderSize) + indexBody
	parity := uint64(HeaderSize) + layout.BlockSize
	shard := index + parity*layout.ShardStride
	fileBody := shard * layout.ParityShardCount
	return parityFilePacketSizes{
		parityShardCount: layout.ParityShardCount,
		indexBody:        indexBody,
		index:            index,
		parity:           parity,
		shard:            shard,
		fileBody:         fileBody,
		file:             fileBody + index,
	}
}

func (p parityFilePacketSizes) calcParityPacketOffset(shardIdx int, stripeIdx int) int64 {
	return int64(p.shard)*int64(shardIdx) + int64(p.index) + int64(p.parity)*int64(stripeIdx)
}

func (p parityFilePacketSizes) calcIndexPacketOffset(shardIdx int) int64 {
	if shardIdx == int(p.parityShardCount) {
		return int64(p.fileBody)
	}
	return int64(p.shard) * int64(shardIdx)
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

	ReadWriteSeekTruncater interface {
		io.ReadWriteSeeker
		Truncate(size int64) error
	}
)

func WriteParityFile(ctx context.Context, log klog.Logger, w WriteSeekTruncater, data io.ReadSeeker, shardCfg ShardConfig, matchFileHash Hash) (Hash, Hash, error) {
	l := klog.NewLevelLogger(log)

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

	indexPacket := parityv0.IndexPacket_builder{
		InputFile: parityv0.InputFile_builder{
			Size: proto.Uint64(layout.FileSize),
		}.Build(),
		ShardConfig: parityv0.ShardConfig_builder{
			BlockSize:   proto.Uint64(layout.BlockSize),
			Count:       proto.Uint64(layout.ShardCount),
			ParityCount: proto.Uint64(layout.ParityShardCount),
		}.Build(),
	}.Build()
	if layout.ShardCount > 0 && layout.ParityShardCount > 0 {
		indexPacket.GetShardConfig().SetCodeMatrixConfig(parityv0.CodeMatrixConfig_builder{
			Kind: proto.String(string(CodeMatrixKindVandermonde)),
		}.Build())
	}
	if layout.NumBlocks > 0 {
		indexPacket.SetBlockSet(initIndexBlocks(layout.NumBlocks, layout.NumParityBlocks))
	}

	start := time.Now()
	fileHash, err := hashDataBlocks(indexPacket, data, *layout)
	duration := time.Since(start)
	if err != nil {
		return emptyHeaderHash, emptyHeaderHash, err
	} else if matchFileHash != emptyHeaderHash && fileHash != matchFileHash {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithKind(nil, ErrFileNoMatch, "Mismatched file hash")
	}
	l.Info(ctx, "Hashed file",
		klog.AString("size", bytefmt.ToString(float64(fileSize))),
		klog.ADuration("duration", duration),
		klog.AString("hashrate", bytefmt.HumanRate(fileSize, duration)),
	)

	packetSizes := calcPacketSizes(uint64(proto.Size(indexPacket)), *layout)

	start = time.Now()
	if err := writeParityPackets(ctx, l, w, data, indexPacket, *layout, packetSizes, nil, nil); err != nil {
		return emptyHeaderHash, emptyHeaderHash, err
	}
	duration = time.Since(start)
	l.Info(ctx, "Wrote parity packets",
		klog.AString("size", bytefmt.ToString(float64(fileSize))),
		klog.ADuration("duration", duration),
		klog.AString("encoderate", bytefmt.HumanRate(fileSize, duration)),
	)

	indexBytes, err := proto.Marshal(indexPacket)
	if err != nil {
		return emptyHeaderHash, emptyHeaderHash, kerrors.WithMsg(err, "Failed marshalling index packet")
	}

	start = time.Now()
	indexPacketHeaderHash, err := writeIndexPackets(w, indexBytes, *layout, packetSizes, nil)
	duration = time.Since(start)
	if err != nil {
		return emptyHeaderHash, emptyHeaderHash, err
	}
	l.Info(ctx, "Wrote index packets",
		klog.AString("size", bytefmt.ToString(float64(fileSize))),
		klog.ADuration("duration", duration),
	)

	return fileHash, indexPacketHeaderHash, nil
}

func writeParityPackets(ctx context.Context, l *klog.LevelLogger, w WriteSeekTruncater, data io.ReadSeeker, indexPacket *parityv0.IndexPacket, layout blockLayout, packetSizes parityFilePacketSizes, validParityStripes, validParityBlocks *bitSet) error {
	if parityFileSize, err := w.Seek(0, io.SeekEnd); err != nil {
		return kerrors.WithMsg(err, "Failed seeking to end of parity file")
	} else if uint64(parityFileSize) != packetSizes.file {
		if err := w.Truncate(int64(packetSizes.file)); err != nil {
			return kerrors.WithMsg(err, "Failed resizing parity file")
		}
	}

	if layout.BlockSize > 0 {
		var enc *reedsolomon.Matrix
		if layout.ParityShardCount > 0 {
			var err error
			enc, err = reedsolomon.NewVandermondeEncoder(int(layout.ShardCount), int(layout.ParityShardCount))
			if err != nil {
				return kerrors.WithKind(err, ErrConfig, "Invalid parity config")
			}
		}

		dataBlockStripeSize := int64(layout.ShardCount * layout.BlockSize)
		parityBlockStripeSize := int64(layout.ParityShardCount * layout.BlockSize)
		allBlockStripeSize := dataBlockStripeSize + parityBlockStripeSize
		dataBlockStripeSizeStr := bytefmt.ToString(float64(layout.ShardCount * layout.BlockSize))
		parityBlockStripeSizeStr := bytefmt.ToString(float64(layout.ParityShardCount * layout.BlockSize))

		allBlocks, buf := allocBlockBuffers(layout.BlockSize, layout.ShardCount+layout.ParityShardCount)
		dataBlocks := allBlocks[:layout.ShardCount]
		parityBlocks := allBlocks[layout.ShardCount:]
		for stripeIdx := range int(layout.ShardStride) {
			if validParityBlocks != nil && validParityStripes.Has(stripeIdx) {
				continue
			}

			// clear buffer before reading
			clear(buf)

			start := time.Now()
			for shardIdx, i := range dataBlocks {
				if layout.isLastShardEmptyBlock(shardIdx, stripeIdx) {
					break
				}
				blockIdx := layout.calcBlockIdx(shardIdx, stripeIdx)
				if _, err := data.Seek(layout.calcDataBlockOffset(blockIdx), io.SeekStart); err != nil {
					return kerrors.WithMsg(err, "Failed seeking input file")
				}
				b := i
				if layout.isLastDataBlock(blockIdx) {
					b = i[:layout.LastBlockSize]
				}
				if _, err := io.ReadFull(data, b); err != nil {
					return kerrors.WithMsg(err, "Failed reading input file")
				}
				h := blake2b.Sum512(b)
				if !bytes.Equal(indexPacket.GetBlockSet().GetInput()[blockIdx].GetHash(), h[:]) {
					return kerrors.WithMsg(nil, "File changed during reading")
				}
			}
			duration := time.Since(start)
			l.Debug(ctx, "Read parity stripe",
				klog.AString("size", dataBlockStripeSizeStr),
				klog.ADuration("duration", duration),
				klog.AString("readrate", bytefmt.HumanRate(dataBlockStripeSize, duration)),
			)

			if enc != nil {
				start = time.Now()
				if err := enc.Encode(dataBlocks, parityBlocks); err != nil {
					return kerrors.WithMsg(err, "Failed encoding parity blocks")
				}
				duration = time.Since(start)
				l.Debug(ctx, "Encode parity stripe",
					klog.AUint64("blocksize", layout.BlockSize),
					klog.AUint64("datashardcount", layout.ShardCount),
					klog.AUint64("parityshardcount", layout.ParityShardCount),
					klog.ADuration("duration", duration),
					klog.AString("encoderate", bytefmt.HumanRate(allBlockStripeSize, duration)),
				)
			}

			start = time.Now()
			for shardIdx, i := range parityBlocks {
				blockIdx := layout.calcBlockIdx(shardIdx, stripeIdx)
				if validParityBlocks != nil && validParityBlocks.Has(blockIdx) {
					continue
				}

				if _, err := w.Seek(packetSizes.calcParityPacketOffset(shardIdx, stripeIdx), io.SeekStart); err != nil {
					return kerrors.WithMsg(err, "Failed seeking parity file")
				}
				h, err := writePacket(w, PacketKindParity, i)
				if err != nil {
					return kerrors.WithMsg(err, "Failed writing parity packet")
				}
				if validParityBlocks != nil {
					if !bytes.Equal(indexPacket.GetBlockSet().GetParity()[blockIdx].GetHash(), h[:]) {
						return kerrors.WithMsg(nil, "Parity packet differs")
					}
				} else {
					copy(indexPacket.GetBlockSet().GetParity()[blockIdx].GetHash(), h[:])
				}
			}
			duration = time.Since(start)
			l.Debug(ctx, "Wrote parity stripe",
				klog.AString("size", parityBlockStripeSizeStr),
				klog.ADuration("duration", duration),
				klog.AString("writerate", bytefmt.HumanRate(parityBlockStripeSize, duration)),
			)
		}
	}
	return nil
}

func writeIndexPackets(w WriteSeekTruncater, indexBytes []byte, layout blockLayout, packetSizes parityFilePacketSizes, validIndexBlocks *bitSet) (Hash, error) {
	if len(indexBytes) > int(packetSizes.indexBody) {
		return emptyHeaderHash, kerrors.WithMsg(nil, "Inconsistent marshalled index packet size")
	}
	for shardIdx := range int(layout.ParityShardCount) {
		if validIndexBlocks != nil && validIndexBlocks.Has(shardIdx) {
			continue
		}
		if _, err := w.Seek(packetSizes.calcIndexPacketOffset(shardIdx), io.SeekStart); err != nil {
			return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
		}
		if _, err := writePacket(w, PacketKindIndex, indexBytes); err != nil {
			return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing index packet")
		}
	}
	if validIndexBlocks != nil && validIndexBlocks.Has(int(layout.ParityShardCount)) {
		header := PacketHeader{
			Version: PacketVersion,
			Length:  uint64(len(indexBytes)),
			Kind:    PacketKindIndex,
		}
		indexPacketHeaderHash, err := calcPacketHash(header, indexBytes)
		if err != nil {
			return emptyHeaderHash, err
		}
		return indexPacketHeaderHash, nil
	}
	if _, err := w.Seek(packetSizes.calcIndexPacketOffset(int(layout.ParityShardCount)), io.SeekStart); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
	}
	indexPacketHeaderHash, err := writePacket(w, PacketKindIndex, indexBytes)
	if err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing index packet")
	}
	return indexPacketHeaderHash, nil
}

func RepairFile(ctx context.Context, log klog.Logger, data, parity ReadWriteSeekTruncater, fileHash, indexPacketHeaderHash Hash, fileSize uint64) error {
	l := klog.NewLevelLogger(log)

	parityFileSize, err := parity.Seek(0, io.SeekEnd)
	if err != nil {
		return kerrors.WithMsg(err, "Failed seeking to end of parity file")
	}

	reader := newStreamReader(parity, nil)

	var indexBytes []byte
	if b, _, err := reader.GetPacket(PacketMatch{Kind: PacketKindIndex, Hash: indexPacketHeaderHash}); err != nil {
		return kerrors.WithMsg(err, "Failed to find index packet")
	} else {
		indexBytes = slices.Clone(b)
	}
	var indexPacket parityv0.IndexPacket
	if err := proto.Unmarshal(indexBytes, &indexPacket); err != nil {
		return kerrors.WithMsg(err, "Failed unmarshalling index packet")
	}

	// perform heuristic check on whether the parity and the data file match
	if !bytes.Equal(fileHash[:], indexPacket.GetInputFile().GetHash()) {
		return kerrors.WithMsg(nil, "Mismatched file hash")
	}
	if indexPacket.GetInputFile().GetSize() != fileSize {
		return kerrors.WithMsg(nil, "Mismatched file size")
	}

	if dataFileSize, err := data.Seek(0, io.SeekEnd); err != nil {
		return kerrors.WithMsg(err, "Failed seeking to end of data file")
	} else if uint64(dataFileSize) != fileSize {
		l.Warn(ctx, "Data file size differs",
			klog.AUint64("expected", fileSize),
			klog.AInt64("actual", dataFileSize),
		)

		if err := data.Truncate(int64(fileSize)); err != nil {
			return kerrors.WithMsg(err, "Failed resizing data file")
		}
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

	packetSizes := calcPacketSizes(uint64(len(indexBytes)), *layout)

	failedRepair := false
	validParityStripes := newBitSet(int(layout.ShardStride))
	validParityBlocks := newBitSet(int(layout.NumParityBlocks))

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

		allBlocks, buf := allocBlockBuffers(layout.BlockSize, layout.ShardCount+layout.ParityShardCount)
		validDataShards := newBitSet(int(layout.ShardCount))
		for stripeIdx := range int(layout.ShardStride) {
			// clear buffer before reading
			clear(buf)
			validDataShards.Clear()

			dataBlocks := allBlocks[:layout.ShardCount]
			parityBlocks := allBlocks[layout.ShardCount:]

			for shardIdx, i := range dataBlocks {
				if layout.isLastShardEmptyBlock(shardIdx, stripeIdx) {
					break
				}
				blockIdx := layout.calcBlockIdx(shardIdx, stripeIdx)
				if _, err := data.Seek(layout.calcDataBlockOffset(blockIdx), io.SeekStart); err != nil {
					return kerrors.WithMsg(err, "Failed seeking data file")
				}
				b := i
				if layout.isLastDataBlock(blockIdx) {
					b = i[:layout.LastBlockSize]
				}
				if _, err := io.ReadFull(data, b); err != nil {
					return kerrors.WithMsg(err, "Failed reading data file")
				}
				h := blake2b.Sum512(b)
				if !bytes.Equal(indexPacket.GetBlockSet().GetInput()[blockIdx].GetHash(), h[:]) {
					// mark data block for repair
					dataBlocks[shardIdx] = dataBlocks[shardIdx][:0]

					l.Warn(ctx, "Block corrupted",
						klog.AString("kind", "data"),
						klog.AInt("idx", blockIdx),
						klog.AInt("shard", shardIdx),
						klog.AInt("stripe", stripeIdx),
					)
				} else {
					validDataShards.Add(shardIdx)

					l.Debug(ctx, "Block ok",
						klog.AString("kind", "data"),
						klog.AInt("idx", blockIdx),
						klog.AInt("shard", shardIdx),
						klog.AInt("stripe", stripeIdx),
					)
				}
			}

			stripeDataBlockCount := layout.calcStripeDataBlocks(stripeIdx)
			hasCorruptedData := validDataShards.Size() != stripeDataBlockCount
			if hasCorruptedData {
				l.Warn(ctx, "Stripe has corrupted blocks",
					klog.AString("kind", "data"),
					klog.AInt("stripe", stripeIdx),
					klog.AInt("count", stripeDataBlockCount-validDataShards.Size()),
				)
			} else {
				l.Debug(ctx, "Stripe blocks ok",
					klog.AString("kind", "data"),
					klog.AInt("stripe", stripeIdx),
				)
			}

			okParityCount := 0
			for shardIdx, i := range parityBlocks {
				var h Hash
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
				okParityCount++
				expectedParityBlockPos := packetSizes.calcParityPacketOffset(shardIdx, stripeIdx)
				validBlockAtPos := parityPos == expectedParityBlockPos
				if !validBlockAtPos && expectedParityBlockPos < parityFileSize {
					ok, err := reader.ValidatePacket(PacketMatch{Kind: PacketKindParity, Hash: h, Length: layout.BlockSize}, expectedParityBlockPos)
					if err != nil {
						return kerrors.WithMsg(err, "Failed reading parity file")
					}
					validBlockAtPos = validBlockAtPos || ok
				}
				if validBlockAtPos {
					validParityBlocks.Add(blockIdx)
					l.Debug(ctx, "Block ok",
						klog.AString("kind", "parity"),
						klog.AInt("idx", blockIdx),
						klog.AInt("shard", shardIdx),
						klog.AInt("stripe", stripeIdx),
					)
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
					klog.AInt("count", len(parityBlocks)-okParityCount),
				)
			}

			if hasCorruptedData {
				if enc == nil {
					failedRepair = true

					l.Error(ctx, "Unable to repair data blocks",
						klog.AInt("stripe", stripeIdx),
						klog.AInt("count.data", validDataShards.Size()),
						klog.AInt("count.parity", okParityCount),
					)
				} else {
					if err := enc.ReconstructData(dataBlocks, parityBlocks); err != nil {
						failedRepair = true

						l.Err(ctx, kerrors.WithMsg(err, "Unable to repair data blocks"),
							klog.AInt("stripe", stripeIdx),
							klog.AInt("count.data", validDataShards.Size()),
							klog.AInt("count.parity", okParityCount),
						)
					}
				}
			}

			for shardIdx, i := range dataBlocks {
				if layout.isLastShardEmptyBlock(shardIdx, stripeIdx) {
					break
				}
				if validDataShards.Has(shardIdx) {
					// skip valid data blocks
					continue
				}

				// write reconstructed data block
				blockIdx := layout.calcBlockIdx(shardIdx, stripeIdx)
				pos := layout.calcDataBlockOffset(blockIdx)
				if _, err := data.Seek(pos, io.SeekStart); err != nil {
					return kerrors.WithMsg(err, "Failed seeking data file")
				}
				b := i
				if layout.isLastDataBlock(blockIdx) {
					b = i[:layout.LastBlockSize]
				}
				if n, err := data.Write(b); err != nil {
					return kerrors.WithMsg(err, "Failed to write to data file")
				} else if n != len(b) {
					return kerrors.WithMsg(io.ErrShortWrite, "Short write")
				}
				l.Info(ctx, "Fixed data block",
					klog.AInt("idx", blockIdx),
					klog.AInt("shard", shardIdx),
					klog.AInt("stripe", stripeIdx),
					klog.AInt64("pos", pos),
					klog.AInt("bytes", len(b)),
				)
			}
		}
	}

	if failedRepair {
		return kerrors.WithKind(nil, ErrFailRepair, "Failed to repair file")
	}

	validIndexBlocks := newBitSet(int(layout.ShardCount) + 1)
	for shardIdx := range int(layout.ParityShardCount) + 1 {
		expectedPos := packetSizes.calcIndexPacketOffset(shardIdx)
		if expectedPos >= parityFileSize {
			continue
		}
		ok, err := reader.ValidatePacket(PacketMatch{Kind: PacketKindIndex, Hash: indexPacketHeaderHash}, expectedPos)
		if err != nil {
			return kerrors.WithMsg(err, "Failed reading parity file")
		}
		if ok {
			validIndexBlocks.Add(shardIdx)
			l.Debug(ctx, "Block ok",
				klog.AString("kind", "index"),
				klog.AInt("shard", shardIdx),
			)
		} else {
			l.Warn(ctx, "Block misplaced",
				klog.AString("kind", "index"),
				klog.AInt("shard", shardIdx),
			)
		}
	}

	// repair any remaining parity blocks
	if err := writeParityPackets(ctx, l, parity, data, &indexPacket, *layout, packetSizes, validParityStripes, validParityBlocks); err != nil {
		return err
	}

	// repair any remaining index blocks
	if _, err := writeIndexPackets(parity, indexBytes, *layout, packetSizes, validIndexBlocks); err != nil {
		return err
	}

	return nil
}
