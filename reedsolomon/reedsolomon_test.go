package reedsolomon

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	gf8Order         = 1 << 8
	gf8MulGroupOrder = gf8Order - 1
)

type (
	gf8Field struct {
		log [gf8Order]byte // log[0] is unused
		exp [gf8MulGroupOrder * 2]byte
	}
)

func newGF8Field(poly, a int) *gf8Field {
	if poly >= gf8Order {
		panic("Invalid generator poly")
	}
	poly |= gf8Order
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
	return f.exp[x]
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
		return gf8MulGroupOrder
	}
	return f.exp[gf8MulGroupOrder-f.log[x]]
}

func (f *gf8Field) Pow(a, b byte) byte {
	if b == 0 {
		return 1
	}
	if a == 0 {
		return 0
	}
	return f.exp[(f.log[a]*b)%gf8MulGroupOrder]
}

func mul(x, y, poly int) int {
	z := 0
	for y > 0 {
		if y&1 != 0 {
			z ^= x
		}
		y >>= 1
		x <<= 1
		if x&gf8Order != 0 {
			x ^= poly
		}
	}
	return z
}

func vandermondeMatrix(field *gf8Field, r, c int) [][]byte {
	m := make([][]byte, r)
	for i := range m {
		k := make([]byte, c)
		for j := range k {
			k[j] = field.Pow(byte(i), byte(j))
		}
		m[i] = k
	}
	return m
}

var errNoInverse = errors.New("No inverse matrix")

func invertMatrix(field *gf8Field, matrix [][]byte) ([][]byte, error) {
	if len(matrix) == 0 {
		return nil, errNoInverse
	}
	if len(matrix[0]) != len(matrix) {
		return nil, errNoInverse
	}
	res := make([][]byte, len(matrix))
	m := make([][]byte, len(matrix))
	for i := range m {
		k := make([]byte, len(matrix)*2)
		copy(k, matrix[i])
		k[len(matrix)+i] = 1
		m[i] = k
		res[i] = make([]byte, len(matrix))
	}
	if err := gaussianEliminate(field, m); err != nil {
		return nil, err
	}
	for n, i := range m {
		copy(res[n], i[len(matrix):])
	}
	return res, nil
}

func gaussianEliminate(field *gf8Field, matrix [][]byte) error {
	m := len(matrix)
	n := len(matrix[0])
	for k := range matrix {
		if matrix[k][k] == 0 {
			for i := k + 1; i < m; i++ {
				if matrix[i][k] != 0 {
					swapRows(matrix, k, n, k, i)
					break
				}
			}
			if matrix[k][k] == 0 {
				return errNoInverse
			}
		}
		if v := matrix[k][k]; v != 1 {
			f := field.Inv(v)
			matrix[k][k] = 1
			for i := k + 1; i < n; i++ {
				matrix[k][i] = field.Mul(matrix[k][i], f)
			}
		}
		for i := k + 1; i < m; i++ {
			if v := matrix[i][k]; v != 0 {
				matrix[i][k] = 0
				for j := k + 1; j < n; j++ {
					matrix[i][j] = field.Add(matrix[i][j], field.Mul(v, matrix[k][j]))
				}
			}
		}
	}
	for k := range matrix {
		for i := 0; i < k; i++ {
			if v := matrix[i][k]; v != 0 {
				matrix[i][k] = 0
				for j := 0; j < n; j++ {
					matrix[i][j] = field.Add(matrix[i][j], field.Mul(v, matrix[k][j]))
				}
			}
		}
	}
	return nil
}

func swapRows(matrix [][]byte, k, n, a, b int) {
	for i := k; i < n; i++ {
		matrix[a][k], matrix[b][k] = matrix[b][k], matrix[a][k]
	}
}

var errNoMatProduct = errors.New("No matrix product")

func matMultiply(field *gf8Field, a, b [][]byte) ([][]byte, error) {
	if len(a) == 0 {
		return nil, errNoMatProduct
	}
	if len(a[0]) != len(b) {
		return nil, errNoMatProduct
	}
	n := len(b[0])
	res := make([][]byte, len(a))
	for i := range res {
		row := a[i]
		r := make([]byte, n)
		for j := range r {
			var v byte
			for k, e := range row {
				v = field.Add(v, field.Mul(e, b[k][j]))
			}
			r[j] = v
		}
		res[i] = r
	}
	return res, nil
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
		{
			inp: 5,
			out: 50,
		},
		{
			inp: 6,
			out: 26,
		},
		{
			inp: 7,
			out: 198,
		},
		{
			inp: 8,
			out: 3,
		},
	} {
		assert.Equal(tc.out, f.Log(tc.inp))
	}

	matrix := vandermondeMatrix(f, 6, 4)
	inverse, err := invertMatrix(f, matrix[:4])
	assert.NoError(err)
	code, err := matMultiply(f, matrix, inverse)
	assert.NoError(err)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if i == j {
				assert.Equal(byte(1), code[i][j], "%d,%d", i, j)
			} else {
				assert.Equal(byte(0), code[i][j], "%d,%d", i, j)
			}
		}
	}
	for _, tc := range []struct {
		i, j int
		v    byte
	}{
		{
			i: 0,
			j: 0,
			v: 0x1b,
		},
		{
			i: 0,
			j: 1,
			v: 0x1c,
		},
		{
			i: 0,
			j: 2,
			v: 0x12,
		},
		{
			i: 0,
			j: 3,
			v: 0x14,
		},
		{
			i: 1,
			j: 0,
			v: 0x1c,
		},
		{
			i: 1,
			j: 1,
			v: 0x1b,
		},
		{
			i: 1,
			j: 2,
			v: 0x14,
		},
		{
			i: 1,
			j: 3,
			v: 0x12,
		},
	} {
		assert.Equal(tc.v, code[4+tc.i][tc.j])
	}

	data := []byte("Hello, world")
	data0 := data[:4]
	data1 := data[4:8]
	data2 := data[8:]
	data3 := []byte{0, 0, 0, 0}
	parity, err := matMultiply(f, code[4:], [][]byte{data0, data1, data2, data3})
	assert.NoError(err)

	enc, err := NewVandermondeEncoder(4, 2)
	assert.NoError(err)

	targetParity := [][]byte{
		{0, 0, 0, 0},
		{0, 0, 0, 0},
	}
	assert.NoError(enc.Encode([][]byte{data0, data1, data2, data3}, targetParity))

	assert.Equal(targetParity, parity)
}
