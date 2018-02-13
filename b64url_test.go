package gose

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
)

var octectTestVectors = []struct {
	octets    []byte
	base64URL []byte
}{
	{
		[]byte{123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32,
			34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125},
		[]byte(`"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"`),
	},
	{
		[]byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
			32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44,
			13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108,
			101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114,
			117, 101, 125},
		[]byte(`"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"`),
	},
}

func TestB64OctetsUnmarshal(t *testing.T) {
	var b64Octets Base64UrlOctets
	for i, v := range octectTestVectors {
		err := json.Unmarshal(v.base64URL, &b64Octets)
		if err != nil {
			t.Errorf("Unable to unmarshal test vector #%d. Err: %v", i+1, err)
		}
		if !bytes.Equal(b64Octets.Octets, v.octets) {
			t.Errorf("Unmarshaled octets don't match. Test vector %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.octets, b64Octets.Octets)
		}
	}
}

func TestB64OctetsMarshal(t *testing.T) {
	var b64Octets *Base64UrlOctets

	for i, v := range octectTestVectors {
		b64Octets = &Base64UrlOctets{Octets: v.octets}
		b64Json, err := json.Marshal(b64Octets)
		if err != nil {
			t.Errorf("Unable to unmarshal test vector #%d. Err: %v", i+1, err)
		}
		if !bytes.Equal(b64Json, v.base64URL) {
			t.Errorf("Mashaled octets don't match. Test vector %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.base64URL, b64Json)
		}
	}
}

var uIntTestVectors = []struct {
	uInt      *big.Int
	base64URL []byte
}{
	{
		(&big.Int{}).SetBytes([]byte{14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212,
			2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211,
			140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143,
			63, 127, 138, 131, 163, 84, 213}),
		[]byte(`"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"`),
	},
}

func TestB64UIntUnmarshal(t *testing.T) {
	var b64UInt Base64UrlUInt
	for i, v := range uIntTestVectors {

		err := json.Unmarshal(v.base64URL, &b64UInt)
		if err != nil {
			t.Errorf("Unable to unmarshal test vector #%d. Err: %v", i+1, err)
		}
		if !bytes.Equal(b64UInt.UInt.Bytes(), v.uInt.Bytes()) {
			t.Errorf("Unmarshaled octets don't match. Test vector %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.uInt.Bytes(), b64UInt.UInt.Bytes())
		}
	}
}

func TestB64UIntMarshal(t *testing.T) {
	var b64UInt *Base64UrlUInt
	for i, v := range uIntTestVectors {
		b64UInt = &Base64UrlUInt{UInt: v.uInt}

		b64Json, err := json.Marshal(b64UInt)
		if err != nil {
			t.Errorf("Unable to unmarshal test vector #%d. Err: %v", i+1, err)
		}
		if !bytes.Equal(b64Json, v.base64URL) {
			t.Errorf("Mashaled octets don't match. Test vector %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.base64URL, b64Json)
		}
	}
}
