package parity

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"

	"github.com/zeebo/blake3"
	"xorkevin.dev/kerrors"
)

var (
	// ErrShortHeader is returned when the provided data is short
	ErrShortHeader errShortHeader
	// ErrMalformedHeader is returned when the header is malformed
	ErrMalformedHeader errHeader
)

type (
	errShortHeader struct{}
	errHeader      struct{}
)

func (e errShortHeader) Error() string {
	return "Short header"
}

func (e errHeader) Error() string {
	return "Malformed header"
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
		b3sum *blake3.Hasher
		count uint64
		w     io.Writer
	}
)

func (h *packetHasher) Write(src []byte) (int, error) {
	if n, err := h.w.Write(src); err != nil {
		return n, err
	}
	n, err := h.b3sum.Write(src)
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

var (
	placeholderHeader = [headerSize]byte{}
	zeroBuf           = [64]byte{}
)

func WritePacket(w io.WriteSeeker, kind PacketKind, data io.Reader) error {
	if _, err := w.Write(placeholderHeader[:]); err != nil {
		return kerrors.WithMsg(err, "Failed to write placeholder packet header")
	}
	header := PacketHeader{
		Version: PacketVersion,
		Kind:    kind,
	}
	hasher := packetHasher{
		b3sum: blake3.New(),
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
		if n := header.Length % 64; n != 0 {
			// pad length to 64 bytes
			l := 64 - n
			if k, err := hasher.b3sum.Write(zeroBuf[:l]); err != nil {
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
		if _, err := hasher.b3sum.Write(buf[:]); err != nil {
			// should not happen as specified by [hash.Hash]
			return kerrors.WithMsg(err, "Failed to write trailer to packet hash")
		}
	}
	copy(header.PacketHash[:], hasher.b3sum.Sum(nil))
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
