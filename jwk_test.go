package gose

import (
	"bytes"
	ec "crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"testing"
)

var jwkTestVectors = []struct {
	name  string
	j     *Jwk
	jJson []byte
}{
	{
		"OCT Key",
		&Jwk{
			Type:              JwkTypeOct,
			Id:                "KEY #1",
			Algorithm:         JwsAlgHS256,
			Use:               KeyUseSig,
			Operations:        KeyOperationSign,
			KeyValue:          []byte("this my symmettric key"),
			AdditionalMembers: map[string]interface{}{"a": 101, "b": "blah"},
		},
		[]byte(`{"a":101,"alg":"HS256","b":"blah","k":"dGhpcyBteSBzeW1tZXR0cmljIGtleQ","key_ops":"sign","kid":"KEY #1","kty":"oct","use":"sig"}`),
	},
	{
		"EC Key",
		&Jwk{
			Type:              JwkTypeEC,
			Id:                "KEY #2",
			Algorithm:         JwsAlgES384,
			Use:               KeyUseSig,
			Operations:        KeyOperationSign,
			X:                 big.NewInt(int64(10333)),
			Y:                 big.NewInt(int64(10334)),
			D:                 big.NewInt(int64(10335)),
			Curve:             ec.P384(),
			AdditionalMembers: map[string]interface{}{"a": 101, "b": "blah"},
		},
		[]byte(`{"a":101,"alg":"ES384","b":"blah","crv":"P-384","d":"KF8","key_ops":"sign","kid":"KEY #2","kty":"EC","use":"sig","x":"KF0","y":"KF4"}`),
	},
	{
		"RSA Key",
		&Jwk{
			Type:       JwkTypeRSA,
			Id:         "KEY #3",
			Algorithm:  JwsAlgPS512,
			Use:        KeyUseSig,
			Operations: KeyOperationSign,
			N:          big.NewInt(int64(10333)),
			E:          25,
			D:          big.NewInt(int64(10335)),
			P:          big.NewInt(int64(10336)),
			Q:          big.NewInt(int64(10337)),
			Dp:         big.NewInt(int64(10338)),
			Dq:         big.NewInt(int64(10339)),
			Qi:         big.NewInt(int64(10340)),
			OtherPrimes: []rsa.CRTValue{
				rsa.CRTValue{Exp: big.NewInt(int64(10341)), Coeff: big.NewInt(int64(10342)), R: big.NewInt(int64(10343))},
				rsa.CRTValue{Exp: big.NewInt(int64(10344)), Coeff: big.NewInt(int64(10345)), R: big.NewInt(int64(10346))},
			},
			AdditionalMembers: map[string]interface{}{"a": 101, "b": "blah"},
		},
		[]byte(`{"a":101,"alg":"PS512","b":"blah","d":"KF8","dp":"KGI","dq":"KGM","e":"GQ","key_ops":"sign","kid":"KEY #3","kty":"RSA","n":"KF0","oth":[{"d":"KGU","t":"KGY","r":"KGc"},{"d":"KGg","t":"KGk","r":"KGo"}],"p":"KGA","q":"KGE","qi":"KGQ","use":"sig"}`),
	},
}

func BenchmarkJwkMarshal(b *testing.B) {
	for n := 0; n < b.N; n++ {
		json.Marshal(jwkTestVectors[2].j)
	}
}

func BenchmarkJwkUnmarshal(b *testing.B) {
	jj := new(Jwk)
	for n := 0; n < b.N; n++ {
		json.Unmarshal(jwkTestVectors[2].jJson, jj)
	}
}

func TestJwkMarshal(t *testing.T) {
	for i, v := range jwkTestVectors {
		data, err := json.Marshal(v.j)
		if err != nil {
			t.Errorf("Unable to Marshal jwk %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.jJson) {
			t.Errorf("Jwk %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.jJson, data)
		}
	}
}

func TestJwkUnmarshal(t *testing.T) {
	for i, v := range jwkTestVectors {
		jTest := new(Jwk)
		err := json.Unmarshal(v.jJson, jTest)
		if err != nil {
			t.Errorf("Unable to Unmarshal jJson %d. Err: %v\n", i+1, err)
		}

		data, err := json.Marshal(jTest)
		if err != nil {
			t.Errorf("Unable to Marshal jwk Json %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.jJson) {
			t.Errorf("Jwk %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.jJson, data)
		}
	}
}
