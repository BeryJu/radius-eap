package eap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPayload_Decode_ShortBuffers(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x02}},
		{"2 bytes", []byte{0x02, 0x01}},
		{"3 bytes", []byte{0x02, 0x01, 0x00}},
		// 4-byte EAP-Success-shaped frame: previously caused panic at raw[5:]
		{"4 bytes EAP-Success-shaped", []byte{0x03, 0x01, 0x00, 0x04}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Payload{}
			err := p.Decode(tc.raw)
			assert.Error(t, err)
		})
	}
}

func TestPayload_Decode_ValidRequest(t *testing.T) {
	// EAP-Identity request: Code=1, ID=1, Length=5, Type=1 (Identity)
	raw := []byte{0x01, 0x01, 0x00, 0x05, 0x01}
	p := &Payload{}
	err := p.Decode(raw)
	// Settings.Protocols is empty so EmptyPayload returns unsupported-type error; no panic.
	require.Error(t, err)
	assert.Equal(t, uint8(0x01), uint8(p.Code))
	assert.Equal(t, uint8(0x01), p.ID)
	assert.Equal(t, uint16(5), p.Length)
}
