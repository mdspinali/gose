package gose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

// Base64Url describes a Base64 URL Encoded, without padding representation of a type
type Base64Url interface {
	Encoded() string
	Decode(string) error
	UnmarshalJSON(data []byte) (err error)
	MarshalJSON() ([]byte, error)
}

// Represents a Base64 URL Encoded, without padding, math/big/Int; referred to as Base64urlUInt-encoded
// in the JWA specification.
// Note: Base64 Encoding/decoding will only occur by json marshalling/unmarshalling or through the
// encoded/decode methods
type Base64UrlUInt struct {
	UInt *big.Int
}

// Represents a Base64 URL Encoded, without padding, byte array; referred to as base64url-encoded
// in the JWS, JWE, JWA, JWT and JWK specifications.
// Note: Base64 Encoding will occur by json marshalling/unmarshalling or through the encoded/decode methods
type Base64UrlOctets struct {
	Octets []byte
}

// Returns the Base64 Encoded value of the math/big/int
func (b *Base64UrlUInt) Encoded() string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b.UInt.Bytes())
}

// Decodes the Base64 Encoded value of the math/big/Int and saves to the decoded value to the
// Base64UrlUInt object. If the decoding cannot be performed and error will be returned
func (b *Base64UrlUInt) Decode(enc string) error {
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(enc)
	if err != nil {
		return errors.New("Unable to decode Base64URLUint-encoded Value")
	}

	b.UInt = new(big.Int)
	b.UInt.SetBytes(decoded)

	return nil
}

// Returns the Base64 Encoded value of the math/big/int
func (b *Base64UrlOctets) Encoded() string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b.Octets)
}

// Decodes the Base64 Encoded value of the math/big/Int and saves to the decoded value to the
// Base64UrlUInt object. If the decoding cannot be performed and error will be returned
func (b *Base64UrlOctets) Decode(enc string) error {
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(enc)
	if err != nil {
		return errors.New("Unable to decode Base64URLBytes-encoded Value")
	}

	b.Octets = decoded

	return nil
}

// Implements the json.Marshaller interface and JSON encodes the base64 URL encoded math/big/Int
func (b *Base64UrlUInt) MarshalJSON() ([]byte, error) {

	return json.Marshal(b.Encoded())
}

// Implements the json.Unmarshaller JSON decodes and then base64 URL decodes the math/big/Int
func (b *Base64UrlUInt) UnmarshalJSON(data []byte) (err error) {
	var b64u string

	if err = json.Unmarshal(data, &b64u); err == nil {
		err = b.Decode(b64u)
	}

	return
}

// JSON encodes the base64 URL []byte
func (b *Base64UrlOctets) MarshalJSON() ([]byte, error) {

	return json.Marshal(b.Encoded())
}

// JSON decodes and the base64 URL []byte
func (b *Base64UrlOctets) UnmarshalJSON(data []byte) (err error) {
	var b64u string

	if err = json.Unmarshal(data, &b64u); err == nil {
		err = b.Decode(b64u)
	}

	return
}
