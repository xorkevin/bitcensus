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
	"golang.org/x/crypto/blake2b"
)

func TestPacketHeader(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	assert.Len([]byte(MagicBytes), 8)
	assert.Equal(headerVersionOffset, len([]byte(MagicBytes)))
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

	packetPayloads := []string{
		`{"hello":"world"}`,
		`{"second":"hello"}`,
		`{"and":"third"}`,
	}
	packetHashes, err := func(packetPayloads []string) (_ [][HeaderHashSize]byte, retErr error) {
		f, err := os.Create(packetfile)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := f.Close(); err != nil {
				retErr = errors.Join(retErr, err)
			}
		}()
		packetHashes := make([][HeaderHashSize]byte, 0, len(packetPayloads))
		for _, i := range packetPayloads {
			h, err := WritePacket(f, PacketKindIndex, strings.NewReader(i))
			if err != nil {
				return nil, err
			}
			packetHashes = append(packetHashes, h)
		}
		return packetHashes, nil
	}(packetPayloads)

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

	for n, i := range packetPayloads {
		var header PacketHeader
		assert.NoError(header.UnmarshalBinary(buf))
		assert.NoError(header.Verify())
		assert.Equal(uint32(PacketVersion), header.Version)
		assert.Equal(uint64(len(i)), header.Length)
		assert.Equal(PacketKindIndex, header.Kind)
		assert.True(len(buf) >= headerSize+int(header.Length))
		assert.Equal(i, string(buf[headerSize:headerSize+int(header.Length)]))
		assert.Equal(packetHashes[n], header.PacketHash)
		var trailer [16]byte
		binary.BigEndian.PutUint32(trailer[:], header.Version)
		binary.LittleEndian.PutUint64(trailer[4:], header.Length)
		binary.BigEndian.PutUint32(trailer[12:], uint32(header.Kind))
		padding := make([]byte, 128-header.Length%128)
		assert.Equal(blake2b.Sum512(append(append([]byte(i), padding...), trailer[:]...)), header.PacketHash)
		buf = buf[headerSize+int(header.Length):]
	}
	assert.Len(buf, 0)
}

func TestPartitionBlocks(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	for _, tc := range []struct {
		fileSize uint64
		cfg      ShardConfig
		exp      *blockLayout
	}{
		{
			fileSize: 32,
			cfg: ShardConfig{
				BlockSize:        5,
				ShardCount:       5,
				ParityShardCount: 2,
			},
			exp: &blockLayout{
				FileSize:           32,
				BlockSize:          5,
				NumBlocks:          7,
				LastBlockSize:      2,
				ShardCount:         4,
				ShardStride:        2,
				NumLastShardBlocks: 1,
				ParityShardCount:   2,
				NumParityBlocks:    4,
			},
		},
	} {
		layout, err := partitionBlocks(tc.fileSize, tc.cfg)
		assert.NoError(err)
		assert.Equal(tc.exp, layout)
		layout2, err := partitionBlocks(layout.FileSize, ShardConfig{
			BlockSize:        layout.BlockSize,
			ShardCount:       layout.ShardCount,
			ParityShardCount: layout.ParityShardCount,
		})
		assert.NoError(err)
		assert.Equal(tc.exp, layout2)
	}
}
