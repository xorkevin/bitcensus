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
)

type (
	errShortHeader    struct{}
	errHeader         struct{}
	errConfig         struct{}
	errPacketNotFound struct{}
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

func WritePacket(w io.Writer, kind PacketKind, data []byte) ([HeaderHashSize]byte, error) {
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

func ReadPacket(r io.Reader, kind PacketKind, hash [HeaderHashSize]byte, length uint64, body []byte) ([]byte, error) {
	buf := body
	if len(buf) < 1024*1024 {
		buf = make([]byte, 1024*1024)
	}
	offset := 0
readmore:
	for {
		b := buf[:offset]
		if remainingHeaderBytes := HeaderSize - offset; remainingHeaderBytes > 0 {
			n, err := io.ReadAtLeast(r, buf[offset:], HeaderSize-offset)
			offset += n
			b = buf[:offset]
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return nil, kerrors.WithKind(err, ErrPacketNotFound, "Packet not found")
				}
				return nil, kerrors.WithMsg(err, "Failed to read parity file")
			}
		}
	nextidx:
		for {
			idx := bytes.Index(b, []byte(MagicBytes))
			if idx < 0 {
				const overlap = len(MagicBytes) - 1
				offset = copy(buf, b[len(b)-overlap:])
				continue readmore
			}
			b = b[idx:]
			if idxFromEnd := len(b); idxFromEnd < HeaderSize {
				offset = copy(buf, b)
				continue readmore
			}
			const unsharedMagicBytesSize = len(MagicBytes)
			var header PacketHeader
			if err := header.UnmarshalBinary(b); err != nil {
				b = b[unsharedMagicBytesSize:]
				continue nextidx
			}
			if err := header.Verify(); err != nil {
				b = b[unsharedMagicBytesSize:]
				continue nextidx
			}
			if header.Kind != kind {
				b = b[unsharedMagicBytesSize:]
				continue nextidx
			}
			if hash != emptyHeaderHash && header.PacketHash != hash {
				b = b[unsharedMagicBytesSize:]
				continue nextidx
			}
			if length != 0 && header.Length != length {
				b = b[unsharedMagicBytesSize:]
				continue nextidx
			}
			if header.Length > maxPacketLength {
				b = b[unsharedMagicBytesSize:]
				continue nextidx
			}

			packetSize := HeaderSize + int(header.Length)
			if remainingCount := packetSize - len(b); remainingCount > 0 {
				// more packet bytes need to be read
				if len(buf)-offset < remainingCount {
					// buf does not have free space to hold the packet
					if len(buf)-len(b) < remainingCount {
						// buf does not have free space to hold the packet after
						// compaction.
						// allocate the required space
						next := make([]byte, packetSize)
						offset = copy(next, b)
						buf = next
					} else {
						// compact buf bytes
						offset = copy(buf, b)
						// buf now has enough room to read the remaining bytes
					}
				}

				n, err := io.ReadAtLeast(r, buf[offset:], remainingCount)
				offset += n
				b = buf[:offset]
				if err != nil {
					if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
						b = b[unsharedMagicBytesSize:]
						continue nextidx
					}
					return nil, kerrors.WithMsg(err, "Failed to read parity file")
				}
			}

			packetBytes := b[HeaderSize:packetSize]
			packetHash, err := calcPacketHash(header, packetBytes)
			if err != nil {
				return nil, err
			}
			if packetHash != header.PacketHash {
				b = b[unsharedMagicBytesSize:]
				continue nextidx
			}
			return packetBytes, nil
		}
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
				h, err := WritePacket(w, PacketKindParity, i)
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
		if _, err := WritePacket(w, PacketKindIndex, indexPacketBytes); err != nil {
			return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing index packet")
		}
	}
	if _, err := w.Seek(int64(parityFileBodySize), io.SeekStart); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed seeking parity file")
	}
	if _, err := WritePacket(w, PacketKindIndex, indexPacketBytes); err != nil {
		return emptyHeaderHash, kerrors.WithMsg(err, "Failed writing index packet")
	}
	return fileHash, nil
}
