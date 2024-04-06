package reedsolomon

import (
	"github.com/klauspost/reedsolomon"
	"xorkevin.dev/kerrors"
)

// ErrShape is returned when the data shape is invalid
var ErrShape errShape

type (
	errShape struct{}
)

func (e errShape) Error() string {
	return "Invalid data shape"
}

type (
	Encoder interface {
		Encode(data, parity [][]byte) error
		ReconstructData(data, parity [][]byte) error
	}

	Matrix struct {
		dataShards   int
		parityShards int
		enc          reedsolomon.Encoder
		shardWork    [][]byte
	}
)

func NewVandermondeEncoder(dataShards, parityShards int) (*Matrix, error) {
	if dataShards < 1 {
		return nil, kerrors.WithKind(nil, ErrShape, "Must have at least 1 data shard")
	}
	if parityShards < 1 {
		return nil, kerrors.WithKind(nil, ErrShape, "Must have at least 1 parity shard")
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, kerrors.WithMsg(err, "Failed to create vandermonde matrix encoder")
	}
	return &Matrix{
		dataShards:   dataShards,
		parityShards: parityShards,
		enc:          enc,
		shardWork:    make([][]byte, dataShards+parityShards),
	}, nil
}

func (m *Matrix) Encode(data, parity [][]byte) error {
	if len(data) != m.dataShards {
		return kerrors.WithKind(nil, ErrShape, "Invalid number of data shards")
	}
	if len(parity) != m.parityShards {
		return kerrors.WithKind(nil, ErrShape, "Invalid number of parity shards")
	}
	blockSize := len(data[0])
	for n, i := range data {
		if len(i) != blockSize {
			return kerrors.WithKind(nil, ErrShape, "Varying data block size")
		}
		m.shardWork[n] = i
	}
	for n, i := range parity {
		if len(i) != blockSize {
			return kerrors.WithKind(nil, ErrShape, "Varying parity block size")
		}
		m.shardWork[m.dataShards+n] = i
	}
	if err := m.enc.Encode(m.shardWork); err != nil {
		return kerrors.WithMsg(err, "Failed to reed solomon encode data")
	}
	return nil
}

func (m *Matrix) ReconstructData(data, parity [][]byte) error {
	if len(data) != m.dataShards {
		return kerrors.WithKind(nil, ErrShape, "Invalid number of data shards")
	}
	if len(parity) != m.parityShards {
		return kerrors.WithKind(nil, ErrShape, "Invalid number of parity shards")
	}
	blockSize := len(data[0])
	for n, i := range data {
		if len(i) != blockSize && len(i) != 0 {
			return kerrors.WithKind(nil, ErrShape, "Varying data block size")
		}
		m.shardWork[n] = i
	}
	for n, i := range parity {
		if len(i) != blockSize && len(i) != 0 {
			return kerrors.WithKind(nil, ErrShape, "Varying parity block size")
		}
		m.shardWork[m.dataShards+n] = i
	}
	if err := m.enc.ReconstructData(m.shardWork); err != nil {
		return kerrors.WithMsg(err, "Failed to reed solomon reconstruct data")
	}
	return nil
}
