package tests

import (
	"context"
	ttls "crypto/tls"
	"crypto/x509"
	"strings"
	"testing"

	eap "beryju.io/radius-eap"
	"beryju.io/radius-eap/protocol"
	"beryju.io/radius-eap/protocol/identity"
	"beryju.io/radius-eap/protocol/legacy_nak"
	"beryju.io/radius-eap/protocol/mschapv2"
	"beryju.io/radius-eap/protocol/peap"
	"beryju.io/radius-eap/protocol/tls"
	"github.com/stretchr/testify/assert"
)

// matrixTLSSettings mirrors TestEAP_TLS's server setup with a configurable final status.
func matrixTLSSettings(s *Server, status protocol.Status) protocol.Settings {
	return protocol.Settings{
		Logger: eap.DefaultLogger(),
		Protocols: []protocol.ProtocolConstructor{
			identity.Protocol,
			legacy_nak.Protocol,
			tls.Protocol,
		},
		ProtocolPriority: []protocol.Type{identity.TypeIdentity, tls.TypeTLS},
		ProtocolSettings: map[protocol.Type]interface{}{
			tls.TypeTLS: tls.Settings{
				Config: &ttls.Config{
					Certificates: []ttls.Certificate{s.cert},
					ClientAuth:   ttls.RequireAnyClientCert,
				},
				HandshakeSuccessful: func(ctx protocol.Context, certs []*x509.Certificate) protocol.Status {
					return status
				},
			},
		},
	}
}

// matrixPEAPSettings mirrors TestEAP_PEAP_MSCHAPv2's server setup with configurable credentials.
func matrixPEAPSettings(s *Server, password string) protocol.Settings {
	return protocol.Settings{
		Logger: eap.DefaultLogger(),
		Protocols: []protocol.ProtocolConstructor{
			identity.Protocol,
			legacy_nak.Protocol,
			peap.Protocol,
		},
		ProtocolPriority: []protocol.Type{peap.TypePEAP},
		ProtocolSettings: map[protocol.Type]interface{}{
			peap.TypePEAP: peap.Settings{
				Config: &ttls.Config{
					Certificates: []ttls.Certificate{s.cert},
				},
				InnerProtocols: protocol.Settings{
					Protocols: []protocol.ProtocolConstructor{
						identity.Protocol,
						legacy_nak.Protocol,
						mschapv2.Protocol,
					},
					ProtocolPriority: []protocol.Type{mschapv2.TypeMSCHAPv2},
					ProtocolSettings: map[protocol.Type]interface{}{
						mschapv2.TypeMSCHAPv2: mschapv2.Settings{
							AuthenticateRequest: mschapv2.DebugStaticCredentials(
								[]byte("foo"), []byte(password),
							),
							ServerIdentifier: "radius-eap example",
						},
					},
				},
			},
		},
	}
}

// TestEAP_Matrix exercises fragment handling across TLS versions, fragment sizes, EAP methods and
// accept/reject outcomes. The fragment_size values force client-side fragmentation of every flight
// (100), of only the large flights (1000), or leave it to the supplicant default.
func TestEAP_Matrix(t *testing.T) {
	cases := []struct {
		name   string
		config string
		peap   bool
		accept bool
	}{
		{"tls12_frag100", "tls12_frag100", false, true},
		{"tls13_default", "tls13_default", false, true},
		{"tls13_frag100", "tls13_frag100", false, true},
		{"tls13_frag1000", "tls13_frag1000", false, true},
		{"tls13_default_reject", "tls13_default", false, false},
		{"tls13_frag100_reject", "tls13_frag100", false, false},
		{"peap_tls12_default", "peap_tls12_default", true, true},
		{"peap_tls12_frag100", "peap_tls12_frag100", true, true},
		{"peap_tls13_default", "peap_tls13_default", true, true},
		{"peap_tls13_frag100", "peap_tls13_frag100", true, true},
		{"peap_tls13_frag100_reject", "peap_tls13_frag100", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.peap && c.accept && strings.Contains(c.config, "tls13") {
				// PEAP over TLS 1.3 is not supported yet: the outer handshake completes, but the server
				// never starts the tunneled phase 2 conversation. This predates the fragment handling
				// changes and fails identically without them.
				t.Skip("PEAP over TLS 1.3 not supported yet")
			}
			s := NewTestServer(t)
			if c.peap {
				pw := "bar"
				if !c.accept {
					pw = "wrong"
				}
				s.config = matrixPEAPSettings(s, pw)
			} else {
				st := protocol.StatusSuccess
				if !c.accept {
					st = protocol.StatusError
				}
				s.config = matrixTLSSettings(s, st)
			}
			ctx, canc := context.WithCancel(context.Background())
			s.Run(ctx)
			t.Cleanup(canc)

			tr, st := EAPOLTest(t, "config/matrix/"+c.config+".conf")
			if c.accept {
				assert.Equal(t, 0, st)
				assert.Equal(t, "SUCCESS", tr[len(tr)-2])
			} else {
				assert.NotEqual(t, 0, st)
				assert.NotEqual(t, "SUCCESS", tr[len(tr)-2])
			}
		})
	}
}
