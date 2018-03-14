package gose

import (
	ec "crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Represents a type of JSON Web Key (JWK)
// See https://tools.ietf.org/html/rfc7518#section-6.1 for more information
const (
	KeyTypeOct string = "oct"
	KeyTypeEC  string = "EC"
	KeyTypeRSA string = "RSA"
)

// Identifies the use for JWK Public keys as specified in:
// https://tools.ietf.org/html/rfc7517#section-4.2
const (
	KeyUseSig string = "sig"
	KeyUseEnc string = "enc"
)

// Identifies the operation the JWK is inteneded for as specified in:
// https://tools.ietf.org/html/rfc7517#section-4.3
type KeyOperation string

const (
	KeyOpSign       string = "sign"
	KeyOpVerify     string = "verify"
	KeyOpEncrypt    string = "encrypt"
	KeyOpDecrypt    string = "decrypt"
	KeyOpWrapKey    string = "wrapkey"
	KeyOpUnwrapKey  string = "unwrapkey"
	KeyOpDeriveKey  string = "derivekey"
	KeyOpDeriveBits string = "derivebits"
)

// Jwk represents a JSON Web Key as specified in in:
// https://tools.ietf.org/html/rfc7517
type Jwk struct {
	Type              string
	Id                string
	Algorithm         string
	Use               string
	Operations        []string
	Curve             ec.Curve
	X                 *big.Int
	Y                 *big.Int
	D                 *big.Int
	N                 *big.Int
	P                 *big.Int
	Q                 *big.Int
	Dp                *big.Int
	Dq                *big.Int
	Qi                *big.Int
	E                 int
	OtherPrimes       []rsa.CRTValue
	KeyValue          []byte
	AdditionalMembers map[string]interface{}
}

// Returns a new JWK for the desired type. An error will be returned if an invalid type is passed
func NewJwk(kty string) (j *Jwk, err error) {
	switch kty {
	case KeyTypeOct, KeyTypeRSA, KeyTypeEC:
		j = &Jwk{Type: kty}
	default:
		err = errors.New("Key Type Invalid. Must be Oct, RSA or EC")
	}

	return
}

// Curve returns the elliptic.Curve for the specificied CrvType. If the CrvType is invalid or unknown,
// a nil Curve type will be returned.
func CurveByName(curveName string) ec.Curve {
	switch curveName {
	case "P-224":
		return ec.P224()
	case "P-256":
		return ec.P256()
	case "P-384":
		return ec.P384()
	case "P-521":
		return ec.P521()
	default:
		return nil
	}
}

type jwkOthPrimeJSON struct {
	Exp   *Base64UrlUInt `json:"d, omitempty"`
	Coeff *Base64UrlUInt `json:"t, omitempty"`
	R     *Base64UrlUInt `json:"r, omitempty"`
}

func (jwk *Jwk) UnmarshalJSON(data []byte) error {
	var obj map[string]json.RawMessage

	// Unmarshal into Map of Json.RawMessages. Each key is the JSON field, each value is the
	// the value of each JSON Field
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return err
	}

	if v, ok := obj["kty"]; ok {
		err = json.Unmarshal(v, &jwk.Type)
		if err != nil {
			return err
		}
		delete(obj, "kty")
	}
	if v, ok := obj["kid"]; ok {
		err = json.Unmarshal(v, &jwk.Id)
		if err != nil {
			return err
		}
		delete(obj, "kid")
	}
	if v, ok := obj["alg"]; ok {
		err = json.Unmarshal(v, &jwk.Algorithm)
		if err != nil {
			return err
		}
		delete(obj, "alg")
	}
	if v, ok := obj["use"]; ok {
		err = json.Unmarshal(v, &jwk.Use)
		if err != nil {
			return err
		}
		delete(obj, "use")
	}
	if v, ok := obj["key_ops"]; ok {
		err = json.Unmarshal(v, &jwk.Operations)
		if err != nil {
			return err
		}
		delete(obj, "key_ops")
	}
	if v, ok := obj["crv"]; ok {
		var eCrv string
		err = json.Unmarshal(v, &eCrv)
		if err != nil {
			return err
		}
		jwk.Curve = CurveByName(eCrv)
		delete(obj, "crv")
	}
	if v, ok := obj["x"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.X = b64u.UInt
		delete(obj, "x")
	}
	if v, ok := obj["y"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.Y = b64u.UInt
		delete(obj, "y")
	}
	if v, ok := obj["d"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.D = b64u.UInt
		delete(obj, "d")
	}
	if v, ok := obj["n"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.N = b64u.UInt
		delete(obj, "n")
	}
	if v, ok := obj["p"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.P = b64u.UInt
		delete(obj, "p")
	}
	if v, ok := obj["q"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.Q = b64u.UInt
		delete(obj, "q")
	}
	if v, ok := obj["dp"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.Dp = b64u.UInt
		delete(obj, "dp")
	}
	if v, ok := obj["dq"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.Dq = b64u.UInt
		delete(obj, "dq")
	}
	if v, ok := obj["qi"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.Qi = b64u.UInt
		delete(obj, "qi")
	}
	if v, ok := obj["e"]; ok {
		b64u := Base64UrlUInt{}
		err = json.Unmarshal(v, &b64u)
		if err != nil {
			return err
		}
		jwk.E = int(b64u.UInt.Int64())
		delete(obj, "e")
	}
	if v, ok := obj["oth"]; ok {
		var tempOthPrimes []jwkOthPrimeJSON

		err = json.Unmarshal(v, &tempOthPrimes)
		if err != nil {
			return err
		}

		jwk.OtherPrimes = make([]rsa.CRTValue, len(tempOthPrimes))

		for i, othPrime := range tempOthPrimes {
			jwk.OtherPrimes[i].Coeff = othPrime.Coeff.UInt
			jwk.OtherPrimes[i].Exp = othPrime.Exp.UInt
			jwk.OtherPrimes[i].R = othPrime.R.UInt
		}
	}
	if v, ok := obj["k"]; ok {
		b64o := Base64UrlOctets{}
		err = json.Unmarshal(v, &b64o)
		if err != nil {
			return err
		}
		jwk.KeyValue = b64o.Octets
		delete(obj, "k")
	}

	// Unmarshal remaing JSON k/v pairs into an interface{}
	if len(obj) > 0 {
		// Allocate AdditionalClaims member to the be the number of remaining keys in obj
		jwk.AdditionalMembers = make(map[string]interface{}, len(obj))

		for k, v := range obj {
			var intfVal interface{}
			err = json.Unmarshal(v, &intfVal)
			if err != nil {
				return err
			}
			jwk.AdditionalMembers[k] = intfVal
		}
	}

	return nil
}

// Implements the json.Marshaler interface and JSON encodes the Jwk
func (jwk *Jwk) MarshalJSON() (data []byte, err error) {

	// Remove any potentionally conflicting claims from the JWK's additional members
	delete(jwk.AdditionalMembers, "kty")
	delete(jwk.AdditionalMembers, "kid")
	delete(jwk.AdditionalMembers, "alg")
	delete(jwk.AdditionalMembers, "use")
	delete(jwk.AdditionalMembers, "key_ops")
	delete(jwk.AdditionalMembers, "crv")
	delete(jwk.AdditionalMembers, "x")
	delete(jwk.AdditionalMembers, "y")
	delete(jwk.AdditionalMembers, "d")
	delete(jwk.AdditionalMembers, "n")
	delete(jwk.AdditionalMembers, "p")
	delete(jwk.AdditionalMembers, "q")
	delete(jwk.AdditionalMembers, "dp")
	delete(jwk.AdditionalMembers, "dq")
	delete(jwk.AdditionalMembers, "qi")
	delete(jwk.AdditionalMembers, "e")
	delete(jwk.AdditionalMembers, "oth")
	delete(jwk.AdditionalMembers, "k")

	// There are additional claims, individually marshal each member
	obj := make(map[string]*json.RawMessage, len(jwk.AdditionalMembers)+10)

	if bytes, err := json.Marshal(jwk.Type); err == nil {
		rm := json.RawMessage(bytes)
		obj["kty"] = &rm
	} else {
		return nil, err
	}

	if len(jwk.Id) > 0 {
		if bytes, err := json.Marshal(jwk.Id); err == nil {
			rm := json.RawMessage(bytes)
			obj["kid"] = &rm
		} else {
			return nil, err
		}
	}
	if len(jwk.Algorithm) > 0 {
		if bytes, err := json.Marshal(jwk.Algorithm); err == nil {
			rm := json.RawMessage(bytes)
			obj["alg"] = &rm
		} else {
			return nil, err
		}
	}
	if len(jwk.Use) > 0 {
		if bytes, err := json.Marshal(jwk.Use); err == nil {
			rm := json.RawMessage(bytes)
			obj["use"] = &rm
		} else {
			return nil, err
		}
	}
	if len(jwk.Operations) > 0 {
		if bytes, err := json.Marshal(jwk.Operations); err == nil {
			rm := json.RawMessage(bytes)
			obj["key_ops"] = &rm
		} else {
			return nil, err
		}
	}

	switch jwk.Type {
	case KeyTypeEC:
		{
			if jwk.Curve != nil {
				jwk.Curve.Params()
				p := jwk.Curve.Params()
				if bytes, err := json.Marshal(p.Name); err == nil {
					rm := json.RawMessage(bytes)
					obj["crv"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.X != nil {
				b64u := &Base64UrlUInt{UInt: jwk.X}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["x"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.Y != nil {
				b64u := &Base64UrlUInt{UInt: jwk.Y}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["y"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.D != nil {
				b64u := &Base64UrlUInt{UInt: jwk.D}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["d"] = &rm
				} else {
					return nil, err
				}
			}
		}
	case KeyTypeRSA:
		{
			if jwk.D != nil {
				b64u := &Base64UrlUInt{UInt: jwk.D}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["d"] = &rm
				} else {
					return nil, err
				}
			}

			if jwk.N != nil {
				b64u := &Base64UrlUInt{UInt: jwk.N}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["n"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.P != nil {
				b64u := &Base64UrlUInt{UInt: jwk.P}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["p"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.Q != nil {
				b64u := &Base64UrlUInt{UInt: jwk.Q}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["q"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.Dp != nil {
				b64u := &Base64UrlUInt{UInt: jwk.Dp}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["dp"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.Dq != nil {
				b64u := &Base64UrlUInt{UInt: jwk.Dq}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["dq"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.Qi != nil {
				b64u := &Base64UrlUInt{UInt: jwk.Qi}
				if bytes, err := json.Marshal(b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["qi"] = &rm
				} else {
					return nil, err
				}
			}
			if jwk.E >= 0 {
				b64u := &Base64UrlUInt{UInt: big.NewInt(int64(jwk.E))}
				if bytes, err := json.Marshal(&b64u); err == nil {
					rm := json.RawMessage(bytes)
					obj["e"] = &rm
				} else {
					return nil, err
				}
			}

			if len(jwk.OtherPrimes) > 0 {
				tempOthPrimes := make([]jwkOthPrimeJSON, len(jwk.OtherPrimes))
				for i, v := range jwk.OtherPrimes {
					tempOthPrimes[i].Coeff = &Base64UrlUInt{UInt: v.Coeff}
					tempOthPrimes[i].Exp = &Base64UrlUInt{UInt: v.Exp}
					tempOthPrimes[i].R = &Base64UrlUInt{UInt: v.R}
				}

				if bytes, err := json.Marshal(tempOthPrimes); err == nil {
					rm := json.RawMessage(bytes)
					obj["oth"] = &rm
				} else {
					return nil, err
				}
			}
		}
	case KeyTypeOct:
		{
			if len(jwk.KeyValue) > 0 {
				b64o := &Base64UrlOctets{Octets: jwk.KeyValue}
				if bytes, err := json.Marshal(b64o); err == nil {
					rm := json.RawMessage(bytes)
					obj["k"] = &rm
				} else {
					return nil, err
				}
			}
		}

	}

	//Iterate through remaing members and add to json rawMessage
	for k, v := range jwk.AdditionalMembers {
		if bytes, err := json.Marshal(v); err == nil {
			rm := json.RawMessage(bytes)
			obj[k] = &rm
		} else {
			return nil, err
		}
	}

	// Marshal obj
	return json.Marshal(obj)
}

// Validate checkes the JWK object to verify the parameter set represent a valid JWK.
// If jwk is valid a nil error will be returned. If a JWK is invalid an error will
// be returned describing the values that causes the validation to fail.
func (jwk *Jwk) Validate() error {

	// If the alg parameter is set, make sure it matches the set JWK Type
	if len(jwk.Algorithm) > 0 {
		algKeyType := GetKeyType(jwk.Algorithm)
		if algKeyType != jwk.Type {
			fmt.Errorf("Jwk Type (kty=%v) doesn't match the algorithm key type (%v)", jwk.Type, algKeyType)
		}
	}
	switch jwk.Type {
	case KeyTypeRSA:
		if err := jwk.validateRSAParams(); err != nil {
			return err
		}

	case KeyTypeEC:
		if err := jwk.validateECParams(); err != nil {
			return err
		}

	case KeyTypeOct:
		if err := jwk.validateOctParams(); err != nil {
			return err
		}

	default:
		return errors.New("KeyType (kty) must be EC, RSA or Oct")
	}

	return nil
}

// ValidateRSAParams checks the RSA parameters of a RSA type of JWK.
// If a JWK is invalid an error will be returned describing the values that causes
// the validation to fail.
func (jwk *Jwk) validateRSAParams() error {
	if jwk.E < 1 {
		return errors.New("RSA Required Param (E) is empty/default (<= 0)")
	}
	if jwk.N == nil {
		return errors.New("RSA Required Param (N) is nil")
	}

	pOk := jwk.P != nil
	qOk := jwk.Q != nil
	dpOk := jwk.Dp != nil
	dqOk := jwk.Dq != nil
	qiOk := jwk.Qi != nil
	othOk := len(jwk.OtherPrimes) > 0

	paramsOR := pOk || qOk || dpOk || dqOk || qiOk
	paramsAnd := pOk && qOk && dpOk && dqOk && qiOk

	if jwk.D == nil {
		if (paramsOR || othOk) == true {
			return errors.New("RSA first/second prime values are present but not Private key value (D)")
		}
	} else {
		if paramsOR != paramsAnd {
			return errors.New("Not all RSA first/second prime values are present or not present")
		} else if !paramsOR && othOk {
			return errors.New("RSA other primes is included but 1st, 2nd prime variables are missing")
		} else if othOk {
			for i, oth := range jwk.OtherPrimes {
				if oth.Coeff == nil {
					return fmt.Errorf("Other Prime at index=%d, Coeff missing/nil", i)
				} else if oth.R == nil {
					return fmt.Errorf("Other Prime at index=%d, R missing/nil", i)
				} else if oth.Exp == nil {
					return fmt.Errorf("Other Prime at index=%d, Exp missing/nil", i)
				}
			}
		}
	}

	return nil
}

// ValidateRSAParams checks the Elliptic parameters of an Elliptic type of JWK.
// If a JWK is invalid an error will be returned describing the values that causes
// the validation to fail.
func (jwk *Jwk) validateECParams() error {
	if jwk.X == nil {
		return errors.New("EC Required Param (X) is nil")
	}
	if jwk.Y == nil {
		return errors.New("EC Required Param (Y) is nil")
	}
	if jwk.Curve == nil {
		return errors.New("EC Required Param (Crv) is nil")
	}
	return nil
}

// ValidateRSAParams checks the Octet (symmetric) parameters of an Octet type of JWK.
// If a JWK is invalid an error will be returned describing the values that causes
// the validation to fail.
func (jwk *Jwk) validateOctParams() error {
	if len(jwk.KeyValue) < 1 {
		return errors.New("Oct Required Param KeyValue (k) is empty")
	}

	return nil
}
