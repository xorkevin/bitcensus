package parity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"xorkevin.dev/bitcensus/pb/parityv0"
	"xorkevin.dev/klog"
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
	assert.Equal(HeaderSize, headerKindOffset+4)

	header := PacketHeader{
		Version:    0,
		PacketHash: [HeaderHashSize]byte{0, 1, 2, 3, 4, 5, 6, 7},
		Length:     8,
		Kind:       1,
	}

	headerBytes, err := header.MarshalBinary()
	assert.NoError(err)
	assert.Len(headerBytes, HeaderSize)

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
			h, err := writePacket(f, PacketKindIndex, []byte(i))
			if err != nil {
				return nil, err
			}
			packetHashes = append(packetHashes, h)
		}
		return packetHashes, nil
	}(packetPayloads)
	assert.NoError(err)

	buf, err := os.ReadFile(packetfile)
	assert.NoError(err)

	reader := newStreamReader(bytes.NewReader(buf), nil)
	for n, i := range packetPayloads {
		var header PacketHeader
		assert.NoError(header.UnmarshalBinary(buf))
		assert.NoError(header.Verify())
		assert.Equal(uint32(PacketVersion), header.Version)
		assert.Equal(uint64(len(i)), header.Length)
		assert.Equal(PacketKindIndex, header.Kind)
		assert.True(len(buf) >= HeaderSize+int(header.Length))
		assert.Equal(i, string(buf[HeaderSize:HeaderSize+int(header.Length)]))
		assert.Equal(packetHashes[n], header.PacketHash)
		var trailer [16]byte
		binary.BigEndian.PutUint32(trailer[:], header.Version)
		binary.LittleEndian.PutUint64(trailer[4:], header.Length)
		binary.BigEndian.PutUint32(trailer[12:], uint32(header.Kind))
		padding := make([]byte, hashBlockSize-header.Length%hashBlockSize)
		assert.Equal(blake2b.Sum512(append(append([]byte(i), padding...), trailer[:]...)), header.PacketHash)

		reader.Reset(bytes.NewReader(buf))
		body, _, err := reader.GetPacket(PacketMatch{Kind: PacketKindIndex})
		assert.NoError(err)
		assert.Equal(i, string(body))

		buf = buf[HeaderSize+int(header.Length):]
	}
	assert.Len(buf, 0)
}

func TestPartitionBlocks(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		fileSize uint64
		cfg      ShardConfig
		exp      *blockLayout
	}{
		{
			name:     "packs shards",
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
		{
			name:     "file smaller than block size",
			fileSize: 32,
			cfg: ShardConfig{
				BlockSize:        64,
				ShardCount:       5,
				ParityShardCount: 2,
			},
			exp: &blockLayout{
				FileSize:           32,
				BlockSize:          32,
				NumBlocks:          1,
				LastBlockSize:      32,
				ShardCount:         1,
				ShardStride:        1,
				NumLastShardBlocks: 1,
				ParityShardCount:   2,
				NumParityBlocks:    2,
			},
		},
		{
			name:     "empty file",
			fileSize: 0,
			cfg: ShardConfig{
				BlockSize:        5,
				ShardCount:       5,
				ParityShardCount: 2,
			},
			exp: &blockLayout{
				FileSize:           0,
				BlockSize:          0,
				NumBlocks:          0,
				LastBlockSize:      0,
				ShardCount:         0,
				ShardStride:        0,
				NumLastShardBlocks: 0,
				ParityShardCount:   2,
				NumParityBlocks:    0,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert := require.New(t)

			layout, err := partitionBlocks(tc.fileSize, tc.cfg)
			assert.NoError(err)
			assert.Equal(tc.exp, layout)
			layout2, err := partitionBlocks(layout.FileSize, ShardConfig{
				BlockSize:        layout.BlockSize,
				ShardCount:       layout.ShardCount,
				ParityShardCount: layout.ParityShardCount,
			})
			assert.NoError(err)
			assert.Equal(layout, layout2)
		})
	}
}

func TestWriteParityFile(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	tmpdir := t.TempDir()

	inpFileName := filepath.Join(tmpdir, "testfile")
	parityFileName := filepath.Join(tmpdir, "parityfile")

	const (
		fileSize         uint64 = 16*256 - 128
		blockSize        uint64 = 256
		shardCount       uint64 = 6
		parityShardCount uint64 = 3
	)
	var expectedHash [HeaderHashSize]byte
	var dataFile [fileSize]byte
	{
		h, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
		assert.NoError(err)
		_, err = io.ReadFull(h, dataFile[:])
		assert.NoError(err)
		assert.NoError(os.WriteFile(inpFileName, dataFile[:], 0o666))
		expectedHash = blake2b.Sum512(dataFile[:])
	}

	fileHash, indexPacketHeaderHash, err := func() (_, _ [HeaderHashSize]byte, retErr error) {
		inp, err := os.Open(inpFileName)
		if err != nil {
			return emptyHeaderHash, emptyHeaderHash, err
		}
		defer func() {
			if err := inp.Close(); err != nil {
				retErr = errors.Join(retErr, err)
			}
		}()
		out, err := os.Create(parityFileName)
		if err != nil {
			return emptyHeaderHash, emptyHeaderHash, err
		}
		defer func() {
			if err := out.Close(); err != nil {
				retErr = errors.Join(retErr, err)
			}
		}()
		return WriteParityFile(out, inp, ShardConfig{
			BlockSize:        blockSize,
			ShardCount:       shardCount,
			ParityShardCount: parityShardCount,
		})
	}()
	assert.NoError(err)
	assert.Equal(expectedHash, fileHash)

	parityFile, err := os.ReadFile(parityFileName)
	assert.NoError(err)

	// search for magic bytes and version to count packets
	// 3 index packets, 9 parity packets, 1 final index packet
	assert.Equal(3+9+1, bytes.Count(parityFile, []byte(MagicBytes+"\x00\x00\x00\x00")))

	var indexPacketHeader PacketHeader
	assert.NoError(indexPacketHeader.UnmarshalBinary(parityFile))
	assert.NoError(indexPacketHeader.Verify())

	var trailer [16]byte
	binary.BigEndian.PutUint32(trailer[:], indexPacketHeader.Version)
	binary.LittleEndian.PutUint64(trailer[4:], indexPacketHeader.Length)
	binary.BigEndian.PutUint32(trailer[12:], uint32(indexPacketHeader.Kind))
	hh, err := blake2b.New512(nil)
	assert.NoError(err)
	_, err = hh.Write(parityFile[HeaderSize : HeaderSize+int(indexPacketHeader.Length)])
	assert.NoError(err)
	_, err = hh.Write(make([]byte, hashBlockSize-indexPacketHeader.Length%hashBlockSize))
	assert.NoError(err)
	_, err = hh.Write(trailer[:])
	assert.NoError(err)
	assert.Equal(hh.Sum(nil), indexPacketHeader.PacketHash[:])

	parityFileReader := bytes.NewReader(parityFile)
	reader := newStreamReader(parityFileReader, make([]byte, 256))
	indexPacketBody, _, err := reader.GetPacket(PacketMatch{Kind: PacketKindIndex, Hash: indexPacketHeaderHash})
	assert.NoError(err)

	var indexPacket parityv0.IndexPacket
	assert.NoError(proto.Unmarshal(indexPacketBody, &indexPacket))

	assert.Equal(fileHash[:], indexPacket.GetInputFile().GetHash())
	assert.Equal(fileSize, indexPacket.GetInputFile().GetSize())
	assert.Equal(blockSize, indexPacket.GetShardConfig().GetBlockSize())
	assert.Equal(shardCount, indexPacket.GetShardConfig().GetCount())
	assert.Equal(parityShardCount, indexPacket.GetShardConfig().GetParityCount())
	assert.Equal(string(CodeMatrixKindVandermonde), indexPacket.GetShardConfig().GetCodeMatrixConfig().GetKind())
	assert.Len(indexPacket.GetBlockSet().GetInput(), 16)
	assert.Len(indexPacket.GetBlockSet().GetParity(), 9)

	for _, i := range indexPacket.GetBlockSet().GetParity() {
		reader.Reset(parityFileReader)

		// ensure that all parity file packets are present
		var h [HeaderHashSize]byte
		copy(h[:], i.GetHash())
		var parityPacketBody []byte
		var err error
		parityPacketBody, _, err = reader.GetPacket(PacketMatch{Kind: PacketKindParity, Hash: h, Length: blockSize})
		assert.NoError(err)
		assert.Len(parityPacketBody, int(blockSize))
	}

	for _, i := range indexPacket.GetBlockSet().GetParity() {
		// use packet cache
		var h [HeaderHashSize]byte
		copy(h[:], i.GetHash())
		var parityPacketBody []byte
		var err error
		parityPacketBody, _, err = reader.GetPacket(PacketMatch{Kind: PacketKindParity, Hash: h, Length: blockSize})
		assert.NoError(err)
		assert.Len(parityPacketBody, int(blockSize))
	}

	var emptyBytes [512]byte
	for i := int64(0); i < int64(fileSize); i += 512 {
		assert.NoError(func() (retErr error) {
			inp, err := os.OpenFile(inpFileName, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer func() {
				if err := inp.Close(); err != nil {
					retErr = errors.Join(retErr, err)
				}
			}()
			if i >= 512 {
				if _, err := inp.Seek(i-512, io.SeekStart); err != nil {
					return err
				}
				_, err = inp.Write(emptyBytes[:])
				if err != nil {
					return err
				}
			}
			parity, err := os.OpenFile(parityFileName, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer func() {
				if err := parity.Close(); err != nil {
					retErr = errors.Join(retErr, err)
				}
			}()
			if err := RepairFile(context.Background(), klog.Discard{}, inp, parity, fileHash, indexPacketHeaderHash, fileSize); err != nil {
				return err
			}
			return nil
		}())
		b, err := os.ReadFile(inpFileName)
		assert.NoError(err)
		assert.Equal(dataFile[:], b)
	}
	for i := int64(0); i < int64(len(parityFile)); i += 512 {
		assert.NoError(func() (retErr error) {
			inp, err := os.OpenFile(inpFileName, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer func() {
				if err := inp.Close(); err != nil {
					retErr = errors.Join(retErr, err)
				}
			}()
			parity, err := os.OpenFile(parityFileName, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer func() {
				if err := parity.Close(); err != nil {
					retErr = errors.Join(retErr, err)
				}
			}()
			if i >= 512 {
				if _, err := parity.Seek(i-512, io.SeekStart); err != nil {
					return err
				}
				_, err = parity.Write(emptyBytes[:])
				if err != nil {
					return err
				}
			}
			if err := RepairFile(context.Background(), klog.Discard{}, inp, parity, fileHash, indexPacketHeaderHash, fileSize); err != nil {
				return err
			}
			return nil
		}())
		b, err := os.ReadFile(parityFileName)
		assert.NoError(err)
		assert.Equal(parityFile, b)
	}
}
