package parity

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"

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
	PacketHeader struct {
		Version    uint32
		headerSum  uint32
		PacketHash [32]byte
		Length     uint64
		Kind       uint32
	}
)

const MagicBytes = "\xd5\x66\x67\x80\x0d\x0a\x1a\x04"

func (h *PacketHeader) MarshalBinary() ([]byte, error) {
	res := make([]byte, 60)
	copy(res, []byte(MagicBytes))
	binary.BigEndian.PutUint32(res[8:], h.Version)
	binary.BigEndian.PutUint32(res[12:], h.Sum())
	copy(res[16:], h.PacketHash[:])
	binary.BigEndian.PutUint64(res[48:], h.Length)
	binary.BigEndian.PutUint32(res[56:], h.Kind)
	return res, nil
}

func (h *PacketHeader) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return kerrors.WithKind(nil, ErrShortHeader, "Short header")
	}
	if !bytes.Equal(data[:8], []byte(MagicBytes)) {
		return kerrors.WithKind(nil, ErrMalformedHeader, "Invalid magic bytes")
	}
	{
		v := binary.BigEndian.Uint32(data[8:12])
		if v != 0 {
			return kerrors.WithKind(nil, ErrMalformedHeader, "Invalid version")
		}
		h.Version = v
	}
	if len(data) < 60 {
		return kerrors.WithKind(nil, ErrShortHeader, "Short header")
	}
	h.headerSum = binary.BigEndian.Uint32(data[12:16])
	copy(h.PacketHash[:], data[16:])
	h.Length = binary.BigEndian.Uint64(data[48:56])
	h.Kind = binary.BigEndian.Uint32(data[56:60])
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
	binary.BigEndian.PutUint32(n[:], h.Kind)
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
