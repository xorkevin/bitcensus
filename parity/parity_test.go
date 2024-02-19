package parity

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCensus(t *testing.T) {
	t.Parallel()

	assert := require.New(t)

	assert.Len([]byte(MagicBytes), 8)

	header := PacketHeader{
		Version:    0,
		PacketHash: [32]byte{0, 1, 2, 3, 4, 5, 6, 7},
		Length:     8,
		Kind:       1,
	}

	headerBytes, err := header.MarshalBinary()
	assert.NoError(err)

	header.SetSum()
	assert.NoError(header.Verify())

	var target PacketHeader
	assert.NoError(target.UnmarshalBinary(headerBytes))
	assert.Equal(header, target)
	assert.NoError(target.Verify())
}
