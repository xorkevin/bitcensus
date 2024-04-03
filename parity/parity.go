package parity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"

	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"xorkevin.dev/bitcensus/pb/parityv0"
	"xorkevin.dev/bitcensus/reedsolomon"
	"xorkevin.dev/kerrors"
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

func (h PacketHeader) MarshalBinary() ([]byte, error) {
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

func (h PacketHeader) Sum() uint32 {
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

func (h PacketHeader) Verify() error {
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
		r      io.ReadSeeker
		buf    byteBuffer
		pos    int
		maxPos int
		cache  map[[HeaderHashSize]byte][]cachedCandidate
	}

	cachedCandidate struct {
		pos     int
		invalid bool
	}
)

func newStreamReader(r io.ReadSeeker, buf []byte) *streamReader {
	return &streamReader{
		r:      r,
		buf:    byteBuffer{buf: buf, read: 0, write: 0},
		pos:    0,
		maxPos: 0,
		cache:  map[[HeaderHashSize]byte][]cachedCandidate{},
	}
}

func (r *streamReader) Reset() {
	r.buf.Reset()
	r.pos = 0
	r.maxPos = 0
	clear(r.cache)
}

func (r *streamReader) linearScanPacket(match packetMatch) ([]byte, error) {
	if err := r.seek(r.maxPos); err != nil {
		return nil, kerrors.WithMsg(err, "Failed seeking to parity file")
	}
	for {
		var header PacketHeader
		var body []byte
		var err error
		header, body, err = r.readPacket(match)
		if err != nil {
			if errors.Is(err, ErrPacketNoMatch) {
				if header.Kind == PacketKindParity {
					r.cache[header.PacketHash] = append(r.cache[header.PacketHash], cachedCandidate{
						pos:     r.pos,
						invalid: false,
					})
				}
			} else if errors.Is(err, ErrMalformedPacket) {
			} else {
				return nil, err
			}

			// advance only one byte to prevent finding same magic bytes on current
			// pos if one exists
			if err := r.advance(1); err != nil {
				return nil, err
			}
			if idx := bytes.Index(r.buf.Bytes(), []byte(MagicBytes)); idx >= 0 {
				if err := r.advance(idx); err != nil {
					return nil, err
				}
				continue
			}
			// keep an overlap amount of bytes because they could be a prefix of a
			// magic bytes completed by the next buffer read
			const overlap = len(MagicBytes) - 1
			// buf read at least full header
			delta := r.buf.Len() - overlap
			if err := r.advance(delta); err != nil {
				return nil, err
			}
			continue
		}
		return body, nil
	}
}

// advance advances the buffer and file position
//
// may only be called from linearScanPacket
func (r *streamReader) advance(delta int) error {
	if err := r.buf.Advance(delta); err != nil {
		return err
	}
	r.pos += delta
	r.maxPos = r.pos
	return nil
}

// seek seeks to a particular position in the file
func (r *streamReader) seek(pos int) error {
	if _, err := r.r.Seek(int64(pos), io.SeekStart); err != nil {
		return err
	}
	r.pos = pos
	return nil
}

type (
	packetMatch struct {
		kind   PacketKind
		hash   [HeaderHashSize]byte
		length uint64
	}
)

func (r *streamReader) readPacket(match packetMatch) (PacketHeader, []byte, error) {
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

	if header.Kind != match.kind {
		return header, nil, kerrors.WithKind(nil, ErrPacketNoMatch, "Packet kind does not match")
	}
	if match.hash != emptyHeaderHash && header.PacketHash != match.hash {
		return header, nil, kerrors.WithKind(nil, ErrPacketNoMatch, "Packet hash does not match")
	}
	if match.length != 0 && header.Length != match.length {
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

func (b byteBuffer) Bytes() []byte {
	return b.buf[b.read:b.write]
}

func (b byteBuffer) Cap() int {
	return len(b.buf)
}

func (b byteBuffer) Len() int {
	return b.write - b.read
}

func (b byteBuffer) Remaining() int {
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
	if layout.BlockSize == 0 {
		return nil, kerrors.WithKind(nil, ErrConfig, "Invalid block size")
	}
	if layout.ShardCount == 0 {
		return nil, kerrors.WithKind(nil, ErrConfig, "Invalid shard count")
	}
	if layout.ShardCount+layout.ParityShardCount > 255 {
		return nil, kerrors.WithKind(nil, ErrConfig, "Shard counts may not exceed 255")
	}
	layout.BlockSize = min(layout.BlockSize, layout.FileSize)
	if layout.FileSize == 0 {
		layout.ShardCount = 0
		return &layout, nil
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
	WriteSeekTruncater interface {
		io.WriteSeeker
		Truncate(size int64) error
	}
)

func WriteParityFile(w WriteSeekTruncater, data io.ReadSeeker, shardCfg ShardConfig) ([HeaderHashSize]byte, error) {
	fileSize, err := data.Seek(0, io.SeekEnd)
	if err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking to end of input file")
	}
	if _, err := data.Seek(0, io.SeekStart); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking to beginning of input file")
	}

	blockLayout, err := partitionBlocks(uint64(fileSize), shardCfg)
	if err != nil {
		return emptyHeaderHash, err
	}

	indexPacket := parityv0.IndexPacket{
		InputFile: &parityv0.InputFile{
			Size: blockLayout.FileSize,
		},
		ShardConfig: &parityv0.ShardConfig{
			BlockSize:   blockLayout.BlockSize,
			Count:       blockLayout.ShardCount,
			ParityCount: blockLayout.ParityShardCount,
		},
	}
	if blockLayout.ShardCount > 0 && blockLayout.ParityShardCount > 0 {
		indexPacket.ShardConfig.CodeMatrixConfig = &parityv0.CodeMatrixConfig{
			Kind: string(CodeMatrixKindVandermonde),
		}
	}
	if blockLayout.NumBlocks > 0 {
		indexPacket.BlockSet = initIndexBlocks(blockLayout.NumBlocks, blockLayout.NumParityBlocks)
	}

	fileHash, err := hashDataBlocks(&indexPacket, data, blockLayout.BlockSize, blockLayout.LastBlockSize)
	if err != nil {
		return emptyHeaderHash, err
	}

	indexPacketBodySize := proto.Size(&indexPacket)
	indexPacketSize := uint64(HeaderSize) + uint64(indexPacketBodySize)
	parityPacketSize := uint64(HeaderSize) + uint64(blockLayout.BlockSize)
	parityShardSize := indexPacketSize + parityPacketSize*uint64(blockLayout.ShardStride)
	parityFileBodySize := parityShardSize * uint64(blockLayout.ParityShardCount)
	if err := w.Truncate(int64(parityFileBodySize + indexPacketSize)); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed resizing parity file")
	}

	if blockLayout.BlockSize > 0 {
		var enc *reedsolomon.Matrix
		if blockLayout.ParityShardCount > 0 {
			var err error
			enc, err = reedsolomon.NewVandermondeEncoder(int(blockLayout.ShardCount), int(blockLayout.ParityShardCount))
			if err != nil {
				return emptyHeaderHash, kerrors.WithKind(err, ErrConfig, "Invalid parity config")
			}
		}

		buf := make([]byte, blockLayout.BlockSize*(blockLayout.ShardCount+blockLayout.ParityShardCount))
		allBlocks := make([][]byte, blockLayout.ShardCount+blockLayout.ParityShardCount)
		for i := range allBlocks {
			start := blockLayout.BlockSize * uint64(i)
			allBlocks[i] = buf[start : start+blockLayout.BlockSize]
		}
		dataBlocks := allBlocks[:blockLayout.ShardCount]
		parityBlocks := allBlocks[blockLayout.ShardCount:]
		for stripeIdx := range blockLayout.ShardStride {
			// clear buffer before reading
			clear(buf)

			for n, i := range dataBlocks {
				if stripeIdx >= blockLayout.NumLastShardBlocks && uint64(n) == blockLayout.ShardCount-1 {
					break
				}
				blockIdx := blockLayout.ShardStride*uint64(n) + stripeIdx
				if _, err := data.Seek(int64(blockLayout.BlockSize)*int64(blockIdx), io.SeekStart); err != nil {
					return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking input file")
				}
				b := i
				if int(blockIdx) == len(indexPacket.BlockSet.Input)-1 {
					b = i[:blockLayout.LastBlockSize]
				}
				if _, err := io.ReadFull(data, b); err != nil {
					return emptyHeaderHash, kerrors.WithMsg(err, "Failed reading input file")
				}
				h := blake2b.Sum512(b)
				if !bytes.Equal(indexPacket.BlockSet.Input[int(blockIdx)].Hash, h[:]) {
					return emptyHeaderHash, kerrors.WithMsg(err, "File changed during reading")
				}
			}

			if enc != nil {
				if err := enc.Encode(dataBlocks, parityBlocks); err != nil {
					return emptyHeaderHash, kerrors.WithMsg(err, "Failed encoding parity blocks")
				}
			}

			for n, i := range parityBlocks {
				if _, err := w.Seek(int64(parityShardSize)*int64(n)+int64(indexPacketSize)+int64(parityPacketSize)*int64(stripeIdx), io.SeekStart); err != nil {
					return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
				}
				h, err := writePacket(w, PacketKindParity, i)
				if err != nil {
					return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing parity packet")
				}
				copy(indexPacket.BlockSet.Parity[int64(blockLayout.ShardStride)*int64(n)+int64(stripeIdx)].Hash, h[:])
			}
		}
	}

	indexPacketBytes, err := proto.Marshal(&indexPacket)
	if err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed marshalling index packet")
	}
	if len(indexPacketBytes) != indexPacketBodySize {
		return emptyHeaderHash, kerrors.WithMsg(err, "Inconsistent marshalled index packet size")
	}
	for i := range blockLayout.ParityShardCount {
		if _, err := w.Seek(int64(parityShardSize)*int64(i), io.SeekStart); err != nil {
			return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
		}
		if _, err := writePacket(w, PacketKindIndex, indexPacketBytes); err != nil {
			return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing index packet")
		}
	}
	if _, err := w.Seek(int64(parityFileBodySize), io.SeekStart); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
	}
	if _, err := writePacket(w, PacketKindIndex, indexPacketBytes); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing index packet")
	}
	return fileHash, nil
}
