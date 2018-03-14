package gose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
)

// ImportKey imports a Go key into the JWK object. The supported Go Key types are:
// rsa.PublicKey, *rsa.PublicKey, rsa.PrivateKey, *rsa.PrivateKey, ecdsa.PublicKey, *ecdsa.PublicKey,
// ecdsa.PrivateKey, *ecdsa.PrivateKey, string, []byte
func (jwk *Jwk) ImportKey(k interface{}) error {
	switch v := k.(type) {
	case *rsa.PublicKey:
		jwk.importRsaPubKey(v)
	case rsa.PublicKey:
		jwk.importRsaPubKey(&v)
	case *rsa.PrivateKey:
		jwk.importRsaPrivKey(v)
	case rsa.PrivateKey:
		jwk.importRsaPrivKey(&v)
	case *ecdsa.PublicKey:
		jwk.importEcdsaPubKey(v)
	case ecdsa.PublicKey:
		jwk.importEcdsaPubKey(&v)
	case *ecdsa.PrivateKey:
		jwk.importEcdsaPrivKey(v)
	case ecdsa.PrivateKey:
		jwk.importEcdsaPrivKey(&v)
	case string:
		if len(v) < 1 {
			return errors.New("String is empty!")
		} else {
			jwk.ClearTypeParams()
			jwk.Type = KeyTypeOct
			jwk.KeyValue = []byte(v)
		}
	case []byte:
		if len(v) < 1 {
			return errors.New("Byte array is empty!")
		} else {
			jwk.ClearTypeParams()
			jwk.Type = KeyTypeOct
			jwk.KeyValue = v
		}
	default:
		return fmt.Errorf("Key must be a: RSA Public/Private Key, ECDSA Public/Private Key, String, Byte slice. Passed Key Type: %T", k)
	}

	return nil
}

// Exports the JWK to a crypto/ecdsa/PublicKey
func (jwk *Jwk) EcdsaPubKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		jwk.Curve,
		jwk.X,
		jwk.Y,
	}
}

// Exports the JWK to a crypto/ecdsa/PrivateKey
func (jwk *Jwk) EcdsaPrivKey() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		*(jwk.EcdsaPubKey()),
		jwk.D,
	}
}

// Exports the JWK to a crypto/rsa/PublicKey
func (jwk *Jwk) RsaPubKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		jwk.N,
		jwk.E,
	}
}

// Exports the JWK to a crypto/rsa/PrivateKey
func (jwk *Jwk) RsaPrivKey() *rsa.PrivateKey {

	pcv := rsa.PrecomputedValues{}
	pcv.Dp = jwk.Dp
	pcv.Dq = jwk.Dq
	pcv.Qinv = jwk.Qi
	pcv.CRTValues = jwk.OtherPrimes

	primes := make([]*big.Int, 0, 2)
	if jwk.P != nil {
		primes = append(primes, jwk.P)
	}
	if jwk.Q != nil {
		primes = append(primes, jwk.Q)
	}
	return &rsa.PrivateKey{
		*(jwk.RsaPubKey()),
		jwk.D,
		primes,
		pcv,
	}
}

func (jwk *Jwk) importEcdsaPubKey(k *ecdsa.PublicKey) {
	jwk.ClearTypeParams()
	jwk.Type = KeyTypeEC

	jwk.Curve = k.Curve
	jwk.X = k.X
	jwk.Y = k.Y
}

func (jwk *Jwk) importEcdsaPrivKey(k *ecdsa.PrivateKey) {
	jwk.ClearTypeParams()
	jwk.Type = KeyTypeEC

	jwk.importEcdsaPubKey(&(k.PublicKey))
	jwk.D = k.D
}

func (jwk *Jwk) importRsaPubKey(k *rsa.PublicKey) {
	jwk.ClearTypeParams()
	jwk.Type = KeyTypeRSA

	jwk.N = k.N
	jwk.E = k.E
}

func (jwk *Jwk) importRsaPrivKey(k *rsa.PrivateKey) {
	jwk.ClearTypeParams()
	jwk.Type = KeyTypeRSA

	jwk.importRsaPubKey(&(k.PublicKey))
	jwk.D = jwk.D
	jwk.Dp = k.Precomputed.Dp
	jwk.Dq = k.Precomputed.Dq
	jwk.Qi = k.Precomputed.Qinv

	if len(k.Primes) > 1 {
		jwk.P = k.Primes[1]
	}
	if len(k.Primes) > 0 {
		jwk.Q = k.Primes[0]
	}

	jwk.OtherPrimes = k.Precomputed.CRTValues
}

// ClearTypeParams will set all Key Type Specific Params (OCT, RSA, EC) to the empty/default state
func (jwk *Jwk) ClearTypeParams() {
	// Clear key type specific params
	jwk.Curve = nil
	jwk.X = nil
	jwk.Y = nil
	jwk.D = nil
	jwk.Dp = nil
	jwk.Dq = nil
	jwk.Qi = nil
	jwk.P = nil
	jwk.Q = nil
	jwk.OtherPrimes = nil
	jwk.N = nil
	jwk.E = -1
	jwk.KeyValue = nil
}
