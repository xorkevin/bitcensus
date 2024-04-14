package bytefmt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToBytes(t *testing.T) {
	t.Parallel()

	for _, i := range []struct {
		Human string
		Bytes uint64
	}{
		{
			Human: "1KiB",
			Bytes: 1024,
		},
		{
			Human: "1M",
			Bytes: 1048576,
		},
	} {
		t.Run(i.Human, func(t *testing.T) {
			assert := require.New(t)

			b, err := ToBytes(i.Human)
			assert.NoError(err)

			assert.Equal(i.Bytes, b)
		})
	}
}

func TestToString(t *testing.T) {
	t.Parallel()

	for _, i := range []struct {
		Human string
		Bytes float64
	}{
		{
			Human: "1.21KiB",
			Bytes: 1234,
		},
		{
			Human: "117.74MiB",
			Bytes: 123456789,
		},
		{
			Human: "1.00MiB",
			Bytes: 1048576,
		},
	} {
		t.Run(i.Human, func(t *testing.T) {
			assert := require.New(t)

			assert.Equal(i.Human, ToString(i.Bytes))
		})
	}
}
