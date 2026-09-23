package mschapv2

import (
	"bytes"
	"errors"
)

type Response struct {
	Challenge  []byte
	NTResponse []byte
	Flags      uint8
}

func ParseResponse(raw []byte) (*Response, error) {
	// Validate minimum length before slicing
	minLength := challengeValueSize + responseReservedSize + responseNTResponseSize + 1
	if len(raw) < minLength {
		return nil, errors.New("MSCHAPv2: response too short")
	}
	res := &Response{}
	res.Challenge = raw[:challengeValueSize]
	if !bytes.Equal(raw[challengeValueSize:challengeValueSize+responseReservedSize], make([]byte, 8)) {
		return nil, errors.New("MSCHAPv2: Reserved bytes not empty?")
	}
	res.NTResponse = raw[challengeValueSize+responseReservedSize : challengeValueSize+responseReservedSize+responseNTResponseSize]
	res.Flags = (raw[challengeValueSize+responseReservedSize+responseNTResponseSize])
	return res, nil
}
