package bytefmt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
			Human: "117.74KiB",
			Bytes: 123456789,
		},
	} {
		t.Run(i.Human, func(t *testing.T) {
			assert := require.New(t)

			assert.Equal(i.Human, ToString(i.Bytes))
		})
	}
}
