package peap

import (
	"encoding/binary"

	"beryju.io/radius-eap/debug"
	"beryju.io/radius-eap/protocol"
	log "github.com/sirupsen/logrus"
)

const TypePEAPExtension protocol.Type = 33

type ExtensionPayload struct {
	AVPs []ExtensionAVP
}

func (ep *ExtensionPayload) Decode(raw []byte) error {
	log.WithField("raw", debug.FormatBytes(raw)).Debugf("PEAP-Extension: decode raw")
	ep.AVPs = []ExtensionAVP{}
	offset := 0
	for {
		if len(raw[offset:]) < 4 {
			return nil
		}
		len := binary.BigEndian.Uint16(raw[offset+2:offset+2+2]) + ExtensionHeaderSize
		avp := &ExtensionAVP{}
		err := avp.Decode(raw[offset : offset+int(len)])
		if err != nil {
			return err
		}
		ep.AVPs = append(ep.AVPs, *avp)
		offset = offset + int(len)
	}
}

func (ep *ExtensionPayload) Encode() ([]byte, error) {
	log.Debug("PEAP-Extension: encode")
	buff := []byte{}
	for _, avp := range ep.AVPs {
		buff = append(buff, avp.Encode()...)
	}
	return buff, nil
}

func (ep *ExtensionPayload) Handle(protocol.Context) protocol.Payload {
	return nil
}

func (ep *ExtensionPayload) Offerable() bool {
	return false
}

func (ep *ExtensionPayload) String() string {
	return "<PEAP Extension Payload>"
}

func (ep *ExtensionPayload) Type() protocol.Type {
	return TypePEAPExtension
}
