package gose

import (
	"encoding/base64"
	"errors"
)

type JSONSerialization string

const (
	JSONSerializationGeneral JSONSerialization = "general"
	JSONSerializationFlat    JSONSerialization = "flat"
)

// Jws represents a JSON Web Signature (JWS) object as specified in:
// https://tools.ietf.org/html/rfc7515
type Jws struct {
	Signatures         []*JwsSignature
	Payload            []byte
	AdditionalMembers  map[string]interface{}
	JSONSerialization  JSONSerialization
	b64URLPayloadCache []byte
}

type JwsSignature struct {
	ProtectedHeader    *JwHeader
	UnprotectedHeader  *JwHeader
	signature          []byte
	b64URLProtHdrCache []byte
}

// Sign attempts to cryptographically sign the passed Base64URLEncoded payload using the configured Signature value
func (jws *Jws) Sign(jwk *Jwk) error {

	// Check if Jws has one or multiple signatures
	if len(jws.Signatures) > 1 {
		return errors.New("More than one signature structure found.")
	}
	// Verify there are not any signatures to sign
	if len(jws.Signatures) < 1 {
		return nil
	}

	return jws.Signatures[0].Sign(jws, jwk)
}

// Verfies a JWS that has a single signature
func (jws *Jws) Verify(jwk *Jwk) error {
	// Check if Jws has one or multiple signatures
	if len(jws.Signatures) > 1 {
		return errors.New("More than one signature structure found.")
	}
	// Verify there are signutes too verify
	if len(jws.Signatures) < 1 {
		return nil
	}

	return jws.Signatures[0].Verify(jws, jwk)

}

// Private function, verifies a JwsSignature object
func (jSig *JwsSignature) Verify(jws *Jws, jwk *Jwk) error {
	sigAlg, err := jSig.GetAlg()
	if err != nil {
		return err
	}

	// Skip if no (alg=None) signing
	if sigAlg == JwsAlgNone {
		return nil
	}

	// Create signer object
	signer, err := NewJwaSigner(sigAlg)
	if err != nil {
		return err
	}

	// Try to set the verification key
	if err := signer.SetVerifyKey(jwk); err != nil {
		return err
	}

	p := make([]byte, len(jSig.b64URLProtHdrCache)+len(jws.b64URLPayloadCache)+1)

	copy(p[:len(jSig.b64URLProtHdrCache)], jSig.b64URLProtHdrCache)
	copy(p[len(jSig.b64URLProtHdrCache):], ".")
	copy(p[len(jSig.b64URLProtHdrCache)+1:], jws.b64URLPayloadCache)

	// Perform verification
	return signer.Verify(p, jSig.signature)
}

func (jSig *JwsSignature) Sign(jws *Jws, jwk *Jwk) error {
	if err := jSig.Validate(); err != nil {
		return err
	}

	sigAlg, _ := jSig.GetAlg()

	// Skip if no (alg=None) signing
	if sigAlg == JwsAlgNone {
		return nil
	}

	// Create a new signer for the desired algorithm
	signer, err := NewJwaSigner(sigAlg)
	if err != nil {
		return err
	}

	// Set the signing key to the key passed into this function
	if err := signer.SetSignKey(jwk); err != nil {
		return err
	}

	// Export the header to Json and then B64 Encode.
	// Append separation dot "."
	// Append b64 URL encoded body
	protHdrJson, err := jSig.ProtectedHeader.MarshalJSON()
	if err != nil {
		return err
	}
	protHdrB64Url := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(protHdrJson)
	b64URLPayload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(jws.Payload)
	p := make([]byte, len(protHdrB64Url)+len(b64URLPayload)+1)
	copy(p[:len(protHdrB64Url)], protHdrB64Url)
	copy(p[len(protHdrB64Url):], ".")
	copy(p[len(protHdrB64Url)+1:], b64URLPayload)

	// Sign protected data
	sig, err := signer.Sign(p)
	if err != nil {
		return err
	}

	jSig.signature = sig

	return nil
}

// Attempts to determine the signing algorithm for a Jws Signature. This may be in the unprotected header or the protected header
// depending on the end-user's implementation. An error is returned if there are conflicts, or no Alg
func (jSig *JwsSignature) GetAlg() (string, error) {
	var algProt string
	var algUnProt string

	if jSig.ProtectedHeader != nil {
		algProt = jSig.ProtectedHeader.Algorithm
	}
	if jSig.UnprotectedHeader != nil {
		algUnProt = jSig.UnprotectedHeader.Algorithm
	}

	if algProt == "" {
		if algUnProt == "" {
			return "", errors.New("No algorithm (alg) found in protected or unprotected header")
		} else if algProt != algUnProt {
			return "", errors.New("Two non-matching algorithm (alg) parameters found in unprotected and protected header")
		} else if !IsValidJwsAlg(algUnProt) {
			return "", errors.New("Unprotected header algorithm (alg) is not valid")
		}
		return algUnProt, nil
	} else {
		if algUnProt != "" && algProt != algUnProt {
			return "", errors.New("Two non-matching algorithm (alg) parameters found in unprotected and protected header")
		} else if !IsValidJwsAlg(algProt) {
			return "", errors.New("protected header algorithm (alg) is not valid")
		}
		return algProt, nil
	}
}

// Attempts to determine the keyId to use for verifying a signature. This may be in the unprotected header or the protected header
// depending on the end-user's implementation. An error is returned if there are conflicts, or no KId was found
func (jSig *JwsSignature) GetKeyId() (string, error) {
	kIdProt := ""
	kIdUnProt := ""

	if jSig.ProtectedHeader != nil {
		kIdProt = jSig.ProtectedHeader.KeyId
	}
	if jSig.UnprotectedHeader != nil {
		kIdProt = jSig.UnprotectedHeader.KeyId
	}

	if kIdProt == "" {
		if kIdUnProt == "" {
			return "", nil
		}
		return kIdUnProt, nil
	} else {
		if kIdUnProt != "" && kIdUnProt != kIdProt {
			return "", errors.New("Unprotected header keyId different than protected header keyId")
		}
		return kIdProt, nil
	}
}

// Validates a Jws's Signature structure. Note this does not verify the signatures signature. That is done with the VerifyWithJwk() and
// VerifyWithJwks() functions. This simply checks to see the header key/value pairs meet the JWS specification
func (jSig *JwsSignature) Validate() error {
	_, err := jSig.GetAlg()
	if err != nil {
		return err
	}

	if _, err := jSig.GetKeyId(); err != nil {
		return err
	}

	if jSig.UnprotectedHeader != nil {
		if jSig.UnprotectedHeader.Critical != nil {
			return errors.New("Crit (e.g. Critical) parameter must only be present in the protected header")
		}
	}

	return nil
}

func (jSig *JwsSignature) Signature() []byte {
	return jSig.signature
}
