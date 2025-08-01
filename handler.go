package eap

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"reflect"

	"beryju.io/radius-eap/protocol"
	"beryju.io/radius-eap/protocol/eap"
	"beryju.io/radius-eap/protocol/legacy_nak"
	"github.com/gorilla/securecookie"
	log "github.com/sirupsen/logrus"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func sendErrorResponse(w radius.ResponseWriter, r *radius.Request) {
	rres := r.Response(radius.CodeAccessReject)
	err := w.Write(rres)
	if err != nil {
		log.WithError(err).Warning("failed to send response")
	}
}

func (p *Packet) HandleRadiusPacket(w radius.ResponseWriter, r *radius.Request) {
	p.r = r
	rst := rfc2865.State_GetString(r.Packet)
	if rst == "" {
		rst = base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(12))
	}
	p.state = rst

	rp := &Packet{r: r}
	rep, err := p.handleEAP(p.eap, p.stm, nil)
	rp.eap = rep

	rres := r.Response(radius.CodeAccessReject)
	if err == nil {
		switch rp.eap.Code {
		case protocol.CodeRequest:
			rres.Code = radius.CodeAccessChallenge
		case protocol.CodeFailure:
			rres.Code = radius.CodeAccessReject
		case protocol.CodeSuccess:
			rres.Code = radius.CodeAccessAccept
		}
	} else {
		rres.Code = radius.CodeAccessReject
		log.WithError(err).Debug("Rejecting request")
	}
	for _, mod := range p.responseModifiers {
		err := mod.ModifyRADIUSResponse(rres, r.Packet)
		if err != nil {
			log.WithError(err).Warning("Root-EAP: failed to modify response packet")
			break
		}
	}

	err = rfc2865.State_SetString(rres, p.state)
	if err != nil {
		log.WithError(err).Warning("failed to set state")
		sendErrorResponse(w, r)
		return
	}
	eapEncoded, err := rp.Encode()
	if err != nil {
		log.WithError(err).Warning("failed to encode response")
		sendErrorResponse(w, r)
		return
	}
	log.WithField("length", len(eapEncoded)).WithField("type", fmt.Sprintf("%T", rp.eap.Payload)).Debug("Root-EAP: encapsulated challenge")
	err = rfc2869.EAPMessage_Set(rres, eapEncoded)
	if err != nil {
		log.WithError(err).Warning("failed to set EAP message")
		sendErrorResponse(w, r)
		return
	}
	err = p.setMessageAuthenticator(rres)
	if err != nil {
		log.WithError(err).Warning("failed to set message authenticator")
		sendErrorResponse(w, r)
		return
	}
	err = w.Write(rres)
	if err != nil {
		log.WithError(err).Warning("failed to send response")
	}
}

func (p *Packet) handleEAP(pp protocol.Payload, stm protocol.StateManager, parentContext *context) (*eap.Payload, error) {
	st := stm.GetEAPState(p.state)
	if st == nil {
		log.Debug("Root-EAP: blank state")
		st = protocol.BlankState(stm.GetEAPSettings())
	}

	nextChallengeToOffer, err := st.GetNextProtocol()
	if err != nil {
		return &eap.Payload{
			Code: protocol.CodeFailure,
			ID:   p.eap.ID,
		}, err
	}

	next := func() (*eap.Payload, error) {
		st.ProtocolIndex += 1
		stm.SetEAPState(p.state, st)
		return p.handleEAP(pp, stm, nil)
	}

	if n, ok := pp.(*eap.Payload).Payload.(*legacy_nak.Payload); ok {
		log.WithField("desired", n.DesiredType).Debug("Root-EAP: received NAK, trying next protocol")
		pp.(*eap.Payload).Payload = nil
		return next()
	}

	np, t, _ := eap.EmptyPayload(stm.GetEAPSettings(), nextChallengeToOffer)

	var ctx *context
	if parentContext != nil {
		ctx = parentContext.Inner(np, t).(*context)
		ctx.settings = stm.GetEAPSettings().ProtocolSettings[np.Type()]
	} else {
		ctx = &context{
			req:         p.r,
			rootPayload: p.eap,
			typeState:   st.TypeState,
			log:         log.WithField("type", fmt.Sprintf("%T", np)).WithField("code", t),
			settings:    stm.GetEAPSettings().ProtocolSettings[t],
		}
		ctx.handleInner = func(pp protocol.Payload, sm protocol.StateManager, ctx protocol.Context) (protocol.Payload, error) {
			return p.handleEAP(pp, sm, ctx.(*context))
		}
	}
	if !np.Offerable() {
		ctx.Log().Debug("Root-EAP: protocol not offerable, skipping")
		return next()
	}
	ctx.Log().Debug("Root-EAP: Passing to protocol")

	res := &eap.Payload{
		Code:    protocol.CodeRequest,
		ID:      p.eap.ID + 1,
		MsgType: t,
	}
	var payload any
	if reflect.TypeOf(pp.(*eap.Payload).Payload) == reflect.TypeOf(np) {
		err := np.Decode(pp.(*eap.Payload).RawPayload)
		if err != nil {
			ctx.log.WithError(err).Warning("failed to decode payload")
		}
	}
	payload = np.Handle(ctx)
	if payload != nil {
		res.Payload = payload.(protocol.Payload)
	}

	stm.SetEAPState(p.state, st)

	if rm, ok := np.(protocol.ResponseModifier); ok {
		ctx.log.Debug("Root-EAP: Registered response modifier")
		p.responseModifiers = append(p.responseModifiers, rm)
	}

	switch ctx.endStatus {
	case protocol.StatusSuccess:
		res.Code = protocol.CodeSuccess
		res.ID -= 1
	case protocol.StatusError:
		res.Code = protocol.CodeFailure
		res.ID -= 1
	case protocol.StatusNextProtocol:
		ctx.log.Debug("Root-EAP: Protocol ended, starting next protocol")
		return next()
	case protocol.StatusUnknown:
	}
	return res, nil
}

func (p *Packet) setMessageAuthenticator(rp *radius.Packet) error {
	_ = rfc2869.MessageAuthenticator_Set(rp, make([]byte, 16))
	hash := hmac.New(md5.New, rp.Secret)
	encode, err := rp.MarshalBinary()
	if err != nil {
		return err
	}
	hash.Write(encode)
	_ = rfc2869.MessageAuthenticator_Set(rp, hash.Sum(nil))
	return nil
}
