package gose

import (
	"bytes"
	"encoding/json"
	//"fmt"
	"testing"
)

var jwsJSONGeneralTestVectors = []struct {
	jws  *Jws
	json []byte
}{
	{
		// From https://tools.ietf.org/html/rfc7515#appendix-A.6
		&Jws{
			Payload: []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58,
				49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109,
				112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125},
			Signatures: []*JwsSignature{
				&JwsSignature{
					ProtectedHeader: &JwHeader{
						Algorithm: JwsAlgRS256,
					},
					UnprotectedHeader: &JwHeader{
						KeyId: "2010-12-29",
					},
					signature: []byte{112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69, 243, 65, 6, 174,
						27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10, 253, 60, 150, 238, 221,
						115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69, 229, 130,
						173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219, 61, 184, 151, 91, 23, 208, 148, 2, 190,
						237, 213, 217, 217, 112, 7, 16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31, 190,
						127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244, 74, 230, 30, 177, 4, 10, 203, 32,
						4, 77, 62, 249, 18, 142, 212, 1, 48, 121, 91, 212, 189, 59, 65, 238, 202, 208, 102, 171, 101, 25,
						129, 253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239, 177, 139, 93, 163, 204, 60,
						46, 176, 47, 158, 58, 65, 214, 18, 202, 173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175,
						132, 157, 105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69, 34, 165, 68, 200, 242,
						122, 122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85,
						102, 181, 90, 193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67, 208, 25, 238, 251, 71},
				},
				&JwsSignature{
					ProtectedHeader: &JwHeader{
						Algorithm: JwsAlgES256,
					},
					UnprotectedHeader: &JwHeader{
						KeyId: "e9bc097a-ce51-4036-9562-d2ade882db0d",
					},
					signature: []byte{14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3,
						58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60, 112, 229, 216,
						241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163,
						84, 213},
				},
			},
			JSONSerialization: JSONSerializationGeneral,
		},
		[]byte(`{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"` +
			`,"signatures":[{"header":{"kid":"2010-12-29"},"protected":"eyJhbGciOiJSUzI1NiJ9","signature":"cC4hiUPoj9Eetdgtv3h` +
			`F80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAyn` +
			`RFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc` +
			`6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"},{"header":{"k` +
			`id":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"protected":"eyJhbGciOiJFUzI1NiJ9","signature":"DtEhU3ljbEg8L38VWAfUA` +
			`qOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}]}`),
	},
}

var jwsJSONFlatTestVectors = []struct {
	jws  *Jws
	json []byte
}{
	{
		// From https://tools.ietf.org/html/rfc7515#appendix-A.6
		&Jws{
			Payload: []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58,
				49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109,
				112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125},
			Signatures: []*JwsSignature{
				&JwsSignature{
					ProtectedHeader: &JwHeader{
						Algorithm: JwsAlgES256,
					},
					UnprotectedHeader: &JwHeader{
						KeyId: "e9bc097a-ce51-4036-9562-d2ade882db0d",
					},
					signature: []byte{14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3,
						58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60, 112, 229, 216,
						241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163,
						84, 213},
				},
			},
			JSONSerialization: JSONSerializationFlat,
		},
		[]byte(`{"header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4` +
			`MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","signature":"` +
			`DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}`),
	},
}

var jwsCompactTestVectors = []struct {
	jws     *Jws
	encoded []byte
}{
	{
		// From https://tools.ietf.org/html/rfc7515#appendix-A.1
		&Jws{
			Payload: []byte(`{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}`),
			Signatures: []*JwsSignature{
				&JwsSignature{
					ProtectedHeader: &JwHeader{
						Algorithm: JwsAlgHS256,
						Type:      "JWT",
					},
					signature: []byte{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22,
						212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121},
				},
			},
		},
		[]byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`),
	},
	{
		// From https://tools.ietf.org/html/rfc7515#appendix-A.1
		&Jws{
			Payload: []byte(`{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}`),
			Signatures: []*JwsSignature{
				&JwsSignature{
					ProtectedHeader: &JwHeader{
						Algorithm: JwsAlgNone,
					},
				},
			},
		},
		[]byte(`eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.`),
	},
}

var jwsSigningTestVectors = []struct {
	signKeyJson   []byte
	verifyKeyJson []byte
	jws           *Jws
}{
	{
		[]byte(`{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`),
		[]byte(`{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`),
		&Jws{
			Payload: []byte(`{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}`),
			Signatures: []*JwsSignature{
				&JwsSignature{
					ProtectedHeader: &JwHeader{
						Algorithm: JwsAlgHS256,
						Type:      "JWT",
					},
				},
			},
		},
	},
}

func TestJwsMarshalGeneral(t *testing.T) {
	for i, v := range jwsJSONGeneralTestVectors {
		data, err := json.Marshal(v.jws)
		if err != nil {
			t.Errorf("Unable to Marshal Jws %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.json) {
			t.Errorf("Jws %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.json, data)
		}
	}
}

func TestJwsMarshalFlat(t *testing.T) {
	for i, v := range jwsJSONFlatTestVectors {
		data, err := json.Marshal(v.jws)
		if err != nil {
			t.Errorf("Unable to Marshal Jws %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.json) {
			t.Errorf("Jws %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.json, data)
		}
	}
}

func TestJwsMarshalCompact(t *testing.T) {
	for i, v := range jwsCompactTestVectors {
		data, err := v.jws.MarshalCompact()
		if err != nil {
			t.Errorf("Unable to Marshal Jws %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.encoded) {
			t.Errorf("Jws %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.encoded, data)
		}
	}
}

func TestJwsUnMarshalGeneral(t *testing.T) {
	for i, v := range jwsJSONGeneralTestVectors {
		jws := new(Jws)
		err := json.Unmarshal(v.json, jws)
		if err != nil {
			t.Errorf("Unable to Unmarshal jws %d. Err: %v\n", i+1, err)
		}

		data, err := json.Marshal(jws)
		if err != nil {
			t.Errorf("Unable to Marshal jws %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.json) {
			t.Errorf("Jws %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.json, data)
		}
	}
}
func TestJwsUnMarshalFlat(t *testing.T) {
	for i, v := range jwsJSONFlatTestVectors {
		jws := new(Jws)
		err := json.Unmarshal(v.json, jws)
		if err != nil {
			t.Errorf("Unable to Unmarshal jws %d. Err: %v\n", i+1, err)
		}

		data, err := json.Marshal(jws)
		if err != nil {
			t.Errorf("Unable to Marshal jws %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.json) {
			t.Errorf("Jws %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.json, data)
		}
	}
}

func TestJwsUnMarshalCompact(t *testing.T) {
	for i, v := range jwsCompactTestVectors {
		jws := new(Jws)
		err := jws.UnmarshalCompact(v.encoded)
		if err != nil {
			t.Errorf("Unable to Unmarshal jws %d. Err: %v\n", i+1, err)
		}

		data, err := jws.MarshalCompact()
		if err != nil {
			t.Errorf("Unable to Marshal jws %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.encoded) {
			t.Errorf("Jws %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.encoded, data)
		}
	}
}

func TestJwsSigningCompact(t *testing.T) {
	for i, v := range jwsSigningTestVectors {
		jwkSign := new(Jwk)

		err := json.Unmarshal(v.signKeyJson, &jwkSign)
		if err != nil {
			t.Errorf("Unable to set unmarshal signing key %d. Err: %v\n", i+1, err)
		}

		jwkVerify := new(Jwk)

		err = json.Unmarshal(v.verifyKeyJson, &jwkVerify)
		if err != nil {
			t.Errorf("Unable to set unmarshal verifying key %d. Err: %v\n", i+1, err)
		}

		// Sign JWS
		err = v.jws.Sign(jwkSign)
		if err != nil {
			t.Errorf("Unable to sign jws %d. Err: %v\n", i+1, err)
		}
		// Marshal Compact
		jwsCompact, err := v.jws.MarshalCompact()
		if err != nil {
			t.Errorf("Unable to Marshal jws %d. Err: %v\n", i+1, err)
		}

		jwsRecv := new(Jws)

		err = jwsRecv.UnmarshalCompact(jwsCompact)
		if err != nil {
			t.Errorf("Unable to unmarshal jws %d. Err: %v\n", i+1, err)
		}
		//fmt.Println(jwsRecv.b64URLPayloadCache)
		//fmt.Println(jwsRecv.Signatures[0].signature)
		//fmt.Println(jwsRecv.Signatures[0].b64URLProtHdrCache)

		// verify JWS
		err = jwsRecv.Verify(jwkVerify)
		if err != nil {
			t.Errorf("Unable to verify jws %d's signature. Err: %v\n", i+1, err)
		}
	}
}

func TestJwsSigningJson(t *testing.T) {
	for i, v := range jwsSigningTestVectors {
		jwkSign := new(Jwk)

		err := json.Unmarshal(v.signKeyJson, &jwkSign)
		if err != nil {
			t.Errorf("Unable to set unmarshal signing key %d. Err: %v\n", i+1, err)
		}

		jwkVerify := new(Jwk)

		err = json.Unmarshal(v.verifyKeyJson, &jwkVerify)
		if err != nil {
			t.Errorf("Unable to set unmarshal verifying key %d. Err: %v\n", i+1, err)
		}

		// Sign JWS
		err = v.jws.Sign(jwkSign)
		if err != nil {
			t.Errorf("Unable to sign jws %d. Err: %v\n", i+1, err)
		}
		//
		// Marshal General
		//
		jwsJson, err := v.jws.MarshalJSON()
		if err != nil {
			t.Errorf("Unable to Marshal general jws %d. Err: %v\n", i+1, err)
		}

		jwsRecv := new(Jws)

		err = jwsRecv.UnmarshalJSON(jwsJson)
		if err != nil {
			t.Errorf("Unable to unmarshal general jws %d. Err: %v\n", i+1, err)
		}

		// verify JWS
		err = jwsRecv.Verify(jwkVerify)
		if err != nil {
			t.Errorf("Unable to verify jws %d's signature. Err: %v\n", i+1, err)
		}

		//
		// Marshal Flat
		//
		v.jws.JSONSerialization = JSONSerializationFlat
		jwsJson, err = v.jws.MarshalJSON()
		if err != nil {
			t.Errorf("Unable to Marshal flat jws %d. Err: %v\n", i+1, err)
		}

		jwsRecv = new(Jws)
		jwsRecv.JSONSerialization = JSONSerializationFlat
		err = jwsRecv.UnmarshalJSON(jwsJson)
		if err != nil {
			t.Errorf("Unable to unmarshal flat jws %d. Err: %v\n", i+1, err)
		}

		// verify JWS
		err = jwsRecv.Verify(jwkVerify)
		if err != nil {
			t.Errorf("Unable to verify jws %d's signature. Err: %v\n", i+1, err)
		}
	}
}
