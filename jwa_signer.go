package gose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// Signer is the interface implemented by types that crypographically sign and verify data
type JwaSigner interface {
	Sign(msg []byte) ([]byte, error)
	Verify(msg, sig []byte) error
	SetSignKey(jwk *Jwk) error
	SetVerifyKey(jwk *Jwk) error
}

type ESSigner struct {
	H       crypto.Hash
	pubKey  *ecdsa.PublicKey
	privKey *ecdsa.PrivateKey
}

type HSSigner struct {
	H   crypto.Hash
	key []byte
}

type PSSigner struct {
	H       crypto.Hash
	pubKey  *rsa.PublicKey
	privKey *rsa.PrivateKey
}

type RSSigner struct {
	H       crypto.Hash
	pubKey  *rsa.PublicKey
	privKey *rsa.PrivateKey
}

type ECPoint struct {
	R *big.Int
	S *big.Int
}

// Returnes a signer a particular JWS Algorithm. An error is returned for an invalid algorithm.
func NewJwaSigner(jwsAlg string) (JwaSigner, error) {
	switch jwsAlg {
	case JwsAlgHS256:
		return &HSSigner{H: crypto.SHA256}, nil
	case JwsAlgHS384:
		return &HSSigner{H: crypto.SHA384}, nil
	case JwsAlgHS512:
		return &HSSigner{H: crypto.SHA512}, nil
	case JwsAlgRS256:
		return &RSSigner{H: crypto.SHA256}, nil
	case JwsAlgRS384:
		return &RSSigner{H: crypto.SHA384}, nil
	case JwsAlgRS512:
		return &RSSigner{H: crypto.SHA512}, nil
	case JwsAlgES256:
		return &ESSigner{H: crypto.SHA256}, nil
	case JwsAlgES384:
		return &ESSigner{H: crypto.SHA384}, nil
	case JwsAlgES512:
		return &ESSigner{H: crypto.SHA512}, nil
	case JwsAlgPS256:
		return &PSSigner{H: crypto.SHA256}, nil
	case JwsAlgPS384:
		return &PSSigner{H: crypto.SHA384}, nil
	case JwsAlgPS512:
		return &PSSigner{H: crypto.SHA512}, nil
	case JwsAlgNone:
		return nil, nil
	default:
		return nil, fmt.Errorf("JWS ALG: %s is not a recognized JWS alg.", jwsAlg)
	}
}

func (es *ESSigner) Sign(msg []byte) ([]byte, error) {

	if (es.privKey) == nil {
		return nil, errors.New("Signer's signing key was not set")
	}

	h := es.H.New()
	h.Write(msg)
	hashed := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, es.privKey, hashed)
	if err != nil {
		return nil, err
	}

	rB := r.Bytes()
	sB := s.Bytes()

	sig := make([]byte, len(rB)+len(sB))
	copy(sig[:len(rB)], rB)
	copy(sig[len(rB):], sB)

	return sig, nil
}

func (hs *HSSigner) Sign(msg []byte) ([]byte, error) {
	if len(hs.key) < 1 {
		return nil, errors.New("Signer's signing key was not set")
	}

	h := hmac.New(hs.H.New, hs.key)
	h.Write(msg)
	return h.Sum(nil), nil
}

func (ps *PSSigner) Sign(msg []byte) ([]byte, error) {
	if (ps.privKey) == nil {
		return nil, errors.New("Signer's signing key was not set")
	}

	h := ps.H.New()
	h.Write(msg)
	hashed := h.Sum(nil)

	return rsa.SignPSS(rand.Reader, ps.privKey, ps.H, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
}

func (rs *RSSigner) Sign(msg []byte) ([]byte, error) {
	if (rs.privKey) == nil {
		return nil, errors.New("Signer's signing key was not set")
	}

	h := rs.H.New()
	h.Write(msg)
	hashed := h.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, rs.privKey, crypto.SHA256, hashed[:])
}

func (es *ESSigner) Verify(msg, sig []byte) error {
	if (es.pubKey) == nil {
		return errors.New("Signer's verifying key was not set")
	}

	h := es.H.New()
	h.Write(msg)
	hashed := h.Sum(nil)

	byteSize := int((es.pubKey.Curve.Params().BitSize) / 8)

	if len(sig) != (2 * byteSize) {
		return errors.New("Signature size incorrect. The signature must match the # of bits of the E-Curve")
	}

	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(sig[:byteSize])
	s.SetBytes(sig[byteSize:])

	if ok := ecdsa.Verify(es.pubKey, hashed, r, s); !ok {
		return errors.New("ECDSA Signatures do not match")
	}

	return nil
}

func (hs *HSSigner) Verify(msg, sig []byte) error {
	if len(hs.key) < 1 {
		return errors.New("Signer's verifying key was not set")
	}

	expectedSig, _ := hs.Sign(msg)
	if eq := hmac.Equal(sig, expectedSig); !eq {
		return errors.New("HMAC Signatures do not match")
	}

	return nil
}

func (ps *PSSigner) Verify(msg, sig []byte) error {
	if (ps.pubKey) == nil {
		return errors.New("Signer's verifying key was not set")
	}

	h := ps.H.New()
	h.Write(msg)
	hashed := h.Sum(nil)

	return rsa.VerifyPSS(ps.pubKey, ps.H, hashed, sig, nil)
}

func (rs *RSSigner) Verify(msg, sig []byte) error {
	if (rs.pubKey) == nil {
		return errors.New("Signer's verifying key was not set")
	}

	h := rs.H.New()
	h.Write(msg)
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(rs.pubKey, rs.H, hashed, sig)
}

func (es *ESSigner) SetSignKey(jwk *Jwk) error {
	es.privKey = jwk.EcdsaPrivKey()

	return nil
}

func (hs *HSSigner) SetSignKey(jwk *Jwk) error {
	if len(jwk.KeyValue) < 1 {
		return errors.New("Key is blank")
	}
	hs.key = jwk.KeyValue
	return nil
}

func (ps *PSSigner) SetSignKey(jwk *Jwk) error {
	ps.privKey = jwk.RsaPrivKey()
	return nil
}

func (rs *RSSigner) SetSignKey(jwk *Jwk) error {
	rs.privKey = jwk.RsaPrivKey()
	return nil
}

func (es *ESSigner) SetVerifyKey(jwk *Jwk) error {
	es.pubKey = jwk.EcdsaPubKey()

	return nil
}

func (hs *HSSigner) SetVerifyKey(jwk *Jwk) error {
	return hs.SetSignKey(jwk)
}

func (ps *PSSigner) SetVerifyKey(jwk *Jwk) error {
	ps.pubKey = jwk.RsaPubKey()
	return nil
}

func (rs *RSSigner) SetVerifyKey(jwk *Jwk) error {
	rs.pubKey = jwk.RsaPubKey()
	return nil
}
