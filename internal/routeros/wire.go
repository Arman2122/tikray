package routeros

import (
	"bufio"
	"io"
)

const (
	maxWordBytes     = 64 << 10
	maxSentenceBytes = 256 << 10
	maxSentenceWords = 256
)

func readSentence(r *bufio.Reader) ([]string, error) {
	var words []string
	// Reserve the terminator so every accepted sentence fits the wire-byte cap.
	total := 1
	for {
		n, prefix, err := readWordLength(r)
		if err != nil {
			if err == io.EOF && len(words) == 0 {
				return nil, io.EOF
			}
			return nil, ErrProtocol
		}
		if n == 0 {
			return words, nil
		}
		// Check the untrusted length before conversion or allocation.
		if n > maxWordBytes || len(words) >= maxSentenceWords || int(n)+prefix > maxSentenceBytes-total {
			return nil, ErrLimit
		}
		total += int(n) + prefix
		word := make([]byte, int(n))
		if _, err := io.ReadFull(r, word); err != nil {
			return nil, ErrProtocol
		}
		words = append(words, string(word))
	}
}

func readWordLength(r *bufio.Reader) (uint32, int, error) {
	first, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return 0, 0, io.EOF
		}
		return 0, 0, ErrProtocol
	}
	var n, minimum uint32
	var extra int
	switch {
	case first < 0x80:
		return uint32(first), 1, nil
	case first < 0xc0:
		n, extra, minimum = uint32(first&0x3f), 1, 0x80
	case first < 0xe0:
		n, extra, minimum = uint32(first&0x1f), 2, 0x4000
	case first < 0xf0:
		n, extra, minimum = uint32(first&0x0f), 3, 0x200000
	case first == 0xf0:
		extra, minimum = 4, 0x10000000
	default:
		return 0, 0, ErrProtocol
	}
	var tail [4]byte
	if _, err := io.ReadFull(r, tail[:extra]); err != nil {
		return 0, 0, ErrProtocol
	}
	for _, b := range tail[:extra] {
		n = n<<8 | uint32(b)
	}
	if n < minimum {
		return 0, 0, ErrProtocol
	}
	return n, extra + 1, nil
}

func encodeSentence(words []string) ([]byte, error) {
	if len(words) == 0 {
		return nil, ErrProtocol
	}
	if len(words) > maxSentenceWords {
		return nil, ErrLimit
	}
	total := 1
	for _, word := range words {
		n := len(word)
		if n == 0 {
			return nil, ErrProtocol
		}
		if n > maxWordBytes {
			return nil, ErrLimit
		}
		prefix := 1
		if n >= 0x4000 {
			prefix = 3
		} else if n >= 0x80 {
			prefix = 2
		}
		if n+prefix > maxSentenceBytes-total {
			return nil, ErrLimit
		}
		total += n + prefix
	}
	encoded := make([]byte, 0, total)
	for _, word := range words {
		n := len(word)
		switch {
		case n < 0x80:
			encoded = append(encoded, byte(n))
		case n < 0x4000:
			encoded = append(encoded, byte(n>>8)|0x80, byte(n))
		default:
			encoded = append(encoded, byte(n>>16)|0xc0, byte(n>>8), byte(n))
		}
		encoded = append(encoded, word...)
	}
	return append(encoded, 0), nil
}
