package bytefmt

import (
	"strconv"
	"strings"
	"time"
	"unicode"

	"xorkevin.dev/kerrors"
)

// ErrFmt is returned when failing to parse human byte representations
var ErrFmt errFmt

type (
	errFmt struct{}
)

func (e errFmt) Error() string {
	return "Invalid byte format"
}

// Byte constants for every 2^(10*n) bytes
const (
	BYTE = 1 << (10 * iota)
	KILOBYTE
	MEGABYTE
	GIGABYTE
	TERABYTE
	PETABYTE
)

// ToBytes transforms human byte representations to int64
func ToBytes(s string) (uint64, error) {
	s = strings.ToUpper(s)

	i := strings.IndexFunc(s, unicode.IsLetter)

	if i < 0 {
		return 0, kerrors.WithKind(nil, ErrFmt, "No unit")
	}

	bytesString, multiple := s[:i], s[i:]
	bytes, err := strconv.ParseUint(bytesString, 10, 64)
	if err != nil {
		return 0, kerrors.WithKind(err, ErrFmt, "Failed to parse number")
	}
	if bytes < 0 {
		return 0, kerrors.WithKind(nil, ErrFmt, "Bytes must be positive")
	}

	switch multiple {
	case "P", "PB", "PIB":
		return bytes * PETABYTE, nil
	case "T", "TB", "TIB":
		return bytes * TERABYTE, nil
	case "G", "GB", "GIB":
		return bytes * GIGABYTE, nil
	case "M", "MB", "MIB":
		return bytes * MEGABYTE, nil
	case "K", "KB", "KIB":
		return bytes * KILOBYTE, nil
	case "B":
		return bytes, nil
	default:
		return 0, kerrors.WithKind(nil, ErrFmt, "Invalid unit")
	}
}

func ToString(bytes float64) string {
	unitname := "B"
	switch {
	case bytes >= PETABYTE:
		bytes /= PETABYTE
		unitname = "PiB"
	case bytes >= TERABYTE:
		bytes /= TERABYTE
		unitname = "TiB"
	case bytes >= GIGABYTE:
		bytes /= GIGABYTE
		unitname = "GiB"
	case bytes >= MEGABYTE:
		bytes /= MEGABYTE
		unitname = "MiB"
	case bytes >= KILOBYTE:
		bytes /= KILOBYTE
		unitname = "KiB"
	}
	return strconv.FormatFloat(bytes, 'f', 2, 64) + unitname
}

func HumanRate(size int64, duration time.Duration) string {
	return ToString(float64(size)/duration.Seconds()) + "/s"
}
