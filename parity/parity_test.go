package parity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeebo/blake3"
)

func TestPacketHeader(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	assert.Len([]byte(MagicBytes), 8)
	assert.Equal(headerVersionOffset, len([]byte(MagicBytes)))
	assert.Len(blake3.New().Sum(nil), HeaderHashSize)
	assert.Equal(headerSumOffset, headerVersionOffset+4)
	assert.Equal(headerHashOffset, headerSumOffset+4)
	assert.Equal(headerLengthOffset, headerHashOffset+HeaderHashSize)
	assert.Equal(headerKindOffset, headerLengthOffset+8)
	assert.Equal(headerSize, headerKindOffset+4)

	header := PacketHeader{
		Version:    0,
		PacketHash: [HeaderHashSize]byte{0, 1, 2, 3, 4, 5, 6, 7},
		Length:     8,
		Kind:       1,
	}

	headerBytes, err := header.MarshalBinary()
	assert.NoError(err)
	assert.Len(headerBytes, headerSize)

	header.SetSum()
	assert.NoError(header.Verify())

	var target PacketHeader
	assert.NoError(target.UnmarshalBinary(headerBytes))
	assert.Equal(header, target)
	assert.NoError(target.Verify())
}

func TestWritePacket(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	tmpDir := t.TempDir()

	packetfile := filepath.Join(tmpDir, "packetfile.bcp")

	testMessage := `{"hello":"world"}`
	testMessage2 := `{"second":"hello"}`
	assert.NoError(func() (retErr error) {
		f, err := os.Create(packetfile)
		if err != nil {
			return err
		}
		defer func() {
			if err := f.Close(); err != nil {
				retErr = errors.Join(retErr, err)
			}
		}()
		if err := WritePacket(f, PacketKindIndex, strings.NewReader(testMessage)); err != nil {
			return err
		}
		if err := WritePacket(f, PacketKindIndex, strings.NewReader(testMessage2)); err != nil {
			return err
		}
		return nil
	}())

	buf, err := func() (_ []byte, retErr error) {
		f, err := os.Open(packetfile)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := f.Close(); err != nil {
				retErr = errors.Join(retErr, err)
			}
		}()
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, f); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}()
	assert.NoError(err)

	var header PacketHeader
	assert.NoError(header.UnmarshalBinary(buf))
	assert.NoError(header.Verify())
	assert.Equal(uint32(PacketVersion), header.Version)
	assert.Equal(uint64(len(testMessage)), header.Length)
	assert.Equal(PacketKindIndex, header.Kind)
	assert.Equal(testMessage, string(buf[headerSize:headerSize+int(header.Length)]))
	var trailer [16]byte
	binary.BigEndian.PutUint32(trailer[:], header.Version)
	binary.LittleEndian.PutUint64(trailer[4:], header.Length)
	binary.BigEndian.PutUint32(trailer[12:], uint32(header.Kind))
	padding := make([]byte, 64-header.Length%64)
	assert.Equal(blake3.Sum256(append(append([]byte(testMessage), padding...), trailer[:]...)), header.PacketHash)
}
