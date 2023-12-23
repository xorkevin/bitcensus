package reedsolomon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	gf8Order         = 256
	gf8MulGroupOrder = gf8Order - 1
)

type (
	gf8Field struct {
		log [gf8Order]byte // log[0] is unused
		exp [gf8MulGroupOrder * 2]byte
	}
)

func newGF8Field(poly, a int) *gf8Field {
	poly = poly | 0x100
	f := &gf8Field{}
	x := 1
	// a^255 is 1
	for i := 0; i < gf8MulGroupOrder; i++ {
		f.exp[i] = byte(x)
		f.exp[i+gf8MulGroupOrder] = byte(x)
		f.log[x] = byte(i)
		x = mul(x, a, poly)
	}
	f.log[0] = gf8MulGroupOrder
	return f
}

func (f *gf8Field) Exp(x byte) byte {
	return f.exp[x%gf8MulGroupOrder]
}

func (f *gf8Field) Log(x byte) byte {
	return f.log[x]
}

func (f *gf8Field) Add(x, y byte) byte {
	return x ^ y
}

func (f *gf8Field) Mul(x, y byte) byte {
	if x == 0 || y == 0 {
		return 0
	}
	return f.exp[int(f.log[x])+int(f.log[y])]
}

func (f *gf8Field) Inv(x byte) byte {
	if x == 0 {
		return 0
	}
	return f.exp[gf8MulGroupOrder-f.log[x]]
}

func mul(x, y, poly int) int {
	z := 0
	for y > 0 {
		if y&1 != 0 {
			z ^= x
		}
		y >>= 1
		x <<= 1
		if x&0x100 != 0 {
			x ^= poly
		}
	}
	return z
}

func TestReedSolomon(t *testing.T) {
	assert := require.New(t)

	f := newGF8Field(29, 2)
	assert.NotNil(f)

	for _, tc := range []struct {
		inp byte
		out byte
	}{
		{
			inp: 1,
			out: 0,
		},
		{
			inp: 2,
			out: 1,
		},
		{
			inp: 3,
			out: 25,
		},
		{
			inp: 4,
			out: 2,
		},
	} {
		assert.Equal(tc.out, f.Log(tc.inp))
	}
}
