package parity

import (
	"bytes"
	"encoding/binary"
	"hash"
	"hash/crc32"
	"io"

	"golang.org/x/crypto/blake2b"
	"xorkevin.dev/bitcensus/pb/parityv0"
	"xorkevin.dev/kerrors"
)

var (
	// ErrShortHeader is returned when the provided data is short
	ErrShortHeader errShortHeader
	// ErrMalformedHeader is returned when the header is malformed
	ErrMalformedHeader errHeader
	// ErrConfig is returned when the parity config is invalid
	ErrConfig errConfig
)

type (
	errShortHeader struct{}
	errHeader      struct{}
	errConfig      struct{}
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

type (
	PacketKind uint32
)

const (
	PacketKindIndex PacketKind = 1
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
	MagicBytes          = "\xd5\x66\x67\x80\x0d\x0a\x1a\x04"
	HeaderHashSize      = 32
	headerVersionOffset = len(MagicBytes)
	headerSumOffset     = headerVersionOffset + 4
	headerHashOffset    = headerSumOffset + 4
	headerLengthOffset  = headerHashOffset + HeaderHashSize
	headerKindOffset    = headerLengthOffset + 8
	headerSize          = headerKindOffset + 4
)

func (h *PacketHeader) MarshalBinary() ([]byte, error) {
	res := make([]byte, headerSize)
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
	if len(data) < headerSize {
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

type (
	packetHasher struct {
		h     hash.Hash
		count uint64
		w     io.Writer
	}
)

func (h *packetHasher) Write(src []byte) (int, error) {
	if n, err := h.w.Write(src); err != nil {
		return n, err
	}
	n, err := h.h.Write(src)
	if err != nil {
		// should not happen as specified by [hash.Hash]
		return n, kerrors.WithMsg(err, "Failed writing to hasher")
	}
	if n != len(src) {
		// should never happen
		return n, kerrors.WithMsg(io.ErrShortWrite, "Short write")
	}
	h.count += uint64(n)
	return n, nil
}

const (
	hashBlockSize = 128
)

var (
	placeholderHeader = [headerSize]byte{}
	hashBlockZeroBuf  = [hashBlockSize]byte{}
)

func WritePacket(w io.WriteSeeker, kind PacketKind, data io.Reader) error {
	if _, err := w.Write(placeholderHeader[:]); err != nil {
		return kerrors.WithMsg(err, "Failed to write placeholder packet header")
	}
	h, err := blake2b.New256(nil)
	if err != nil {
		return kerrors.WithMsg(err, "Failed to create packet hash")
	}
	header := PacketHeader{
		Version: PacketVersion,
		Kind:    kind,
	}
	hasher := packetHasher{
		h:     h,
		count: 0,
		w:     w,
	}
	if _, err := io.Copy(&hasher, data); err != nil {
		return kerrors.WithMsg(err, "Failed writing packet body")
	}
	totalSize := int64(hasher.count) + int64(headerSize)
	if _, err := w.Seek(-totalSize, io.SeekCurrent); err != nil {
		return kerrors.WithMsg(err, "Failed to seek written packet")
	}
	header.Length = hasher.count
	{
		if n := header.Length % hashBlockSize; n != 0 {
			// pad length to hashBlockSize bytes
			l := hashBlockSize - n
			if k, err := hasher.h.Write(hashBlockZeroBuf[:l]); err != nil {
				// should not happen as specified by [hash.Hash]
				return kerrors.WithMsg(err, "Failed to write padding to packet hash")
			} else if k != int(l) {
				// should never happen
				return kerrors.WithMsg(io.ErrShortWrite, "Short write")
			}
		}
		var buf [16]byte
		binary.BigEndian.PutUint32(buf[:], header.Version)
		binary.LittleEndian.PutUint64(buf[4:], header.Length)
		binary.BigEndian.PutUint32(buf[12:], uint32(header.Kind))
		if _, err := hasher.h.Write(buf[:]); err != nil {
			// should not happen as specified by [hash.Hash]
			return kerrors.WithMsg(err, "Failed to write trailer to packet hash")
		}
	}
	copy(header.PacketHash[:], hasher.h.Sum(nil))
	headerBytes, err := header.MarshalBinary()
	if err != nil {
		return kerrors.WithMsg(err, "Failed to marshal packet header")
	}
	if _, err := w.Write(headerBytes); err != nil {
		return kerrors.WithMsg(err, "Failed to write packet header")
	}
	if _, err := w.Seek(int64(header.Length), io.SeekCurrent); err != nil {
		return kerrors.WithMsg(err, "Failed to seek written packet")
	}
	return nil
}

type (
	blockLayout struct {
		FileSize           uint64
		BlockSize          uint64
		NumBlocks          uint64
		LastBlockSize      uint64
		ShardCount         uint64
		ShardStride        uint64
		NumLastShardBlocks uint64
	}
)

func partitionBlocks(pkt *parityv0.IndexPacket) (*blockLayout, error) {
	cfg := pkt.GetShardConfig()
	layout := blockLayout{
		FileSize:   pkt.GetInputFile().GetSize(),
		BlockSize:  cfg.GetBlockSize(),
		ShardCount: cfg.GetCount(),
	}
	if layout.FileSize == 0 {
		return nil, kerrors.WithKind(nil, ErrConfig, "Empty file")
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
	return &layout, nil
}
