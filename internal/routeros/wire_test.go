package routeros

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestWireWordLengthForms(t *testing.T) {
	tests := []struct {
		value uint32
		wire  []byte
	}{
		{0, []byte{0}},
		{0x7f, []byte{0x7f}},
		{0x80, []byte{0x80, 0x80}},
		{0x3fff, []byte{0xbf, 0xff}},
		{0x4000, []byte{0xc0, 0x40, 0}},
		{0x1fffff, []byte{0xdf, 0xff, 0xff}},
		{0x200000, []byte{0xe0, 0x20, 0, 0}},
		{0xfffffff, []byte{0xef, 0xff, 0xff, 0xff}},
		{0x10000000, []byte{0xf0, 0x10, 0, 0, 0}},
		{0xffffffff, []byte{0xf0, 0xff, 0xff, 0xff, 0xff}},
	}
	for i, tt := range tests {
		n, prefix, err := readWordLength(bufio.NewReader(wireByteReader{bytes.NewReader(tt.wire)}))
		if err != nil || n != tt.value || prefix != len(tt.wire) {
			t.Fatalf("length fixture %d decoded incorrectly", i)
		}
	}
}

func TestWireLengthEncoding(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		prefix []byte
	}{
		{"one", 1, []byte{1}},
		{"one_byte_max", 127, []byte{0x7f}},
		{"two_byte_min", 128, []byte{0x80, 0x80}},
		{"two_byte_max", 16383, []byte{0xbf, 0xff}},
		{"three_byte_min", 16384, []byte{0xc0, 0x40, 0x00}},
		{"word_limit", 64 << 10, []byte{0xc1, 0x00, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			word := strings.Repeat("x", tt.size)
			want := append(append(append([]byte{}, tt.prefix...), word...), 0)
			got, err := encodeSentence([]string{word})
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("encoding differs from protocol length fixture")
			}
			// A network read need not return a complete length or word.
			words, err := readSentence(bufio.NewReader(wireByteReader{bytes.NewReader(want)}))
			if err != nil || len(words) != 1 || words[0] != word {
				t.Fatal("decoding a fragmented word failed")
			}
		})
	}
}

func TestWireSentenceSequence(t *testing.T) {
	first := []string{"!re", "=value=\x00\xffé=x", ".tag=1"}
	second := []string{"!done", ".tag=2"}
	var stream []byte
	for _, sentence := range [][]string{first, second} {
		encoded, err := encodeSentence(sentence)
		if err != nil {
			t.Fatal("encoding fixture failed")
		}
		stream = append(stream, encoded...)
	}
	r := bufio.NewReader(bytes.NewReader(stream))
	for _, want := range [][]string{first, second} {
		got, err := readSentence(r)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("decoding did not preserve sentence boundaries or binary data")
		}
	}
	if got, err := readSentence(r); !errors.Is(err, io.EOF) || got != nil {
		t.Fatal("clean stream end did not return EOF without words")
	}
	if got, err := readSentence(bufio.NewReader(bytes.NewReader([]byte{0}))); err != nil || len(got) != 0 {
		t.Fatal("empty incoming sentence was not accepted")
	}
}

func TestWireBoundsAndSecretTraps(t *testing.T) {
	canary := "wire-private-canary"
	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{"truncated_two_byte_length", []byte{0x80}, ErrProtocol},
		{"truncated_three_byte_length", []byte{0xc0, 0x40}, ErrProtocol},
		{"truncated_four_byte_length", []byte{0xe0, 0x20, 0x00}, ErrProtocol},
		{"truncated_five_byte_length", []byte{0xf0, 0x10, 0x00, 0x00}, ErrProtocol},
		{"noncanonical_two_byte_zero", []byte{0x80, 0x00}, ErrProtocol},
		{"noncanonical_two_byte_length", []byte{0x80, 0x7f}, ErrProtocol},
		{"noncanonical_three_byte_length", []byte{0xc0, 0x3f, 0xff}, ErrProtocol},
		{"noncanonical_four_byte_length", []byte{0xe0, 0x1f, 0xff, 0xff}, ErrProtocol},
		{"noncanonical_five_byte_length", []byte{0xf0, 0x0f, 0xff, 0xff, 0xff}, ErrProtocol},
		{"word_limit_exceeded", []byte{0xc1, 0x00, 0x01}, ErrLimit},
		{"three_byte_maximum", []byte{0xdf, 0xff, 0xff}, ErrLimit},
		{"four_byte_minimum", []byte{0xe0, 0x20, 0x00, 0x00}, ErrLimit},
		{"four_byte_maximum", []byte{0xef, 0xff, 0xff, 0xff}, ErrLimit},
		{"five_byte_minimum", []byte{0xf0, 0x10, 0x00, 0x00, 0x00}, ErrLimit},
		{"five_byte_maximum", []byte{0xf0, 0xff, 0xff, 0xff, 0xff}, ErrLimit},
		{"truncated_word", append([]byte{byte(len(canary) + 1)}, canary...), ErrProtocol},
		{"missing_terminator", append([]byte{byte(len(canary))}, canary...), ErrProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readSentence(bufio.NewReader(bytes.NewReader(tt.wire)))
			if !errors.Is(err, tt.want) || got != nil {
				t.Fatal("malformed sentence did not return the expected fixed category without words")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatal("protocol error exposed peer data")
			}
		})
	}
	for first := 0xf1; first <= 0xff; first++ {
		got, err := readSentence(bufio.NewReader(bytes.NewReader([]byte{byte(first)})))
		if !errors.Is(err, ErrProtocol) || got != nil {
			t.Fatal("unsupported length control was accepted")
		}
	}
	for _, prefix := range [][]byte{nil, {3, '!'}} {
		r := io.MultiReader(bytes.NewReader(prefix), wireErrorReader{errors.New(canary)})
		got, err := readSentence(bufio.NewReader(r))
		if !errors.Is(err, ErrProtocol) || got != nil || strings.Contains(err.Error(), canary) {
			t.Fatal("reader error was not redacted")
		}
	}
}

func TestWireSentenceBounds(t *testing.T) {
	// Four three-byte length prefixes and the terminator count toward the cap.
	atLimit := []string{
		strings.Repeat("x", 64<<10), strings.Repeat("x", 64<<10),
		strings.Repeat("x", 64<<10), strings.Repeat("x", (64<<10)-13),
	}
	encoded, err := encodeSentence(atLimit)
	if err != nil || len(encoded) != 256<<10 {
		t.Fatal("exact sentence byte limit was refused")
	}
	got, err := readSentence(bufio.NewReader(bytes.NewReader(encoded)))
	if err != nil || !reflect.DeepEqual(got, atLimit) {
		t.Fatal("decoding exact sentence byte limit failed")
	}
	tooLong := append([]string{}, atLimit...)
	tooLong[3] += "x"
	if got, err := encodeSentence(tooLong); !errors.Is(err, ErrLimit) || got != nil {
		t.Fatal("encoding over the sentence byte limit succeeded")
	}
	// Increase the last word length and add its payload without using the encoder.
	oversized := append([]byte{}, encoded...)
	lastStart := 3 * ((64 << 10) + 3)
	oversized[lastStart+2]++
	oversized[len(oversized)-1] = 'x'
	oversized = append(oversized, 0)
	if got, err := readSentence(bufio.NewReader(bytes.NewReader(oversized))); !errors.Is(err, ErrLimit) || got != nil {
		t.Fatal("decoding over the sentence byte limit succeeded")
	}

	words := make([]string, 256)
	for i := range words {
		words[i] = "x"
	}
	encoded, err = encodeSentence(words)
	if err != nil {
		t.Fatal("exact word count limit was refused")
	}
	if got, err := readSentence(bufio.NewReader(bytes.NewReader(encoded))); err != nil || len(got) != 256 {
		t.Fatal("decoding exact word count limit failed")
	}
	if got, err := encodeSentence(append(words, "x")); !errors.Is(err, ErrLimit) || got != nil {
		t.Fatal("encoding over the word count limit succeeded")
	}
	tooMany := append(bytes.Repeat([]byte{1, 'x'}, 257), 0)
	if got, err := readSentence(bufio.NewReader(bytes.NewReader(tooMany))); !errors.Is(err, ErrLimit) || got != nil {
		t.Fatal("decoding over the word count limit succeeded")
	}
}

func TestWireInvalidEncode(t *testing.T) {
	for _, words := range [][]string{nil, {}, {""}, {"/print", ""}, {"", "/print"}} {
		if got, err := encodeSentence(words); !errors.Is(err, ErrProtocol) || got != nil {
			t.Fatal("empty outgoing words were accepted")
		}
	}
	if got, err := encodeSentence([]string{strings.Repeat("x", (64<<10)+1)}); !errors.Is(err, ErrLimit) || got != nil {
		t.Fatal("outgoing word limit was not enforced")
	}
}

func FuzzReadSentence(f *testing.F) {
	for _, seed := range [][]byte{{0}, {1, 'x', 0}, {0x80}, {0xf0, 0xff, 0xff, 0xff, 0xff}, {0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		words, err := readSentence(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			if words != nil || (err != ErrProtocol && err != ErrLimit && err != io.EOF) {
				t.Fatal("invalid input returned partial words or an unexpected error")
			}
			return
		}
		if len(words) == 0 {
			return
		}
		encoded, err := encodeSentence(words)
		if err != nil || len(encoded) > maxSentenceBytes {
			t.Fatal("accepted sentence could not be encoded within the byte limit")
		}
		roundTrip, err := readSentence(bufio.NewReader(bytes.NewReader(encoded)))
		if err != nil || !reflect.DeepEqual(words, roundTrip) {
			t.Fatal("accepted sentence did not survive a round trip")
		}
	})
}

type wireByteReader struct{ io.Reader }

func (r wireByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

type wireErrorReader struct{ err error }

func (r wireErrorReader) Read([]byte) (int, error) { return 0, r.err }
