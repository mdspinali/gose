package gose

import (
//"encoding/json"
//"fmt"
)

func GetKeyType(alg string) string {
	switch alg {
	case JwsAlgRS256, JwsAlgRS384, JwsAlgRS512, JwsAlgPS256, JwsAlgPS384, JwsAlgPS512, JweAlgRSA1_5,
		JweAlgRSA_OAEP, JweAlgRSA_OAEP_256:
		return KeyTypeRSA
	case JweAlgDir, JweAlgA128KW, JweAlgA128GCMKW, JweAlgA192KW, JweAlgA192GCMKW, JweAlgA256KW,
		JweAlgA256GCMKW, JweAlgPBES2_HS256_A128KW, JweAlgPBES2_HS384_A192KW,
		JweAlgPBES2_HS512_A256KW, JwsAlgHS256, JwsAlgHS384, JwsAlgHS512:
		return KeyTypeOct
	case JweAlgECDH_ES, JweAlgECDH_ES_A128KW, JweAlgECDH_ES_A192KW, JweAlgECDH_ES_A256KW, JwsAlgES256,
		JwsAlgES384, JwsAlgES512:
		return KeyTypeEC
	}

	return ""
}

// JwsAlg represents a signature algorithm used for JSON Web Signatures (JWS).
// See https://tools.ietf.org/html/rfc7518#section-3 for more information
const (
	JwsAlgHS256 string = "HS256"
	JwsAlgHS384 string = "HS384"
	JwsAlgHS512 string = "HS512"
	JwsAlgRS256 string = "RS256"
	JwsAlgRS384 string = "RS384"
	JwsAlgRS512 string = "RS512"
	JwsAlgES256 string = "ES256"
	JwsAlgES384 string = "ES384"
	JwsAlgES512 string = "ES512"
	JwsAlgPS256 string = "PS256"
	JwsAlgPS384 string = "PS384"
	JwsAlgPS512 string = "PS512"
	JwsAlgNone  string = "none"
)

func IsValidJwsAlg(alg string) bool {
	switch alg {
	case JwsAlgRS256, JwsAlgRS384, JwsAlgRS512, JwsAlgPS256, JwsAlgPS384, JwsAlgPS512, JwsAlgHS256,
		JwsAlgHS384, JwsAlgHS512, JwsAlgES256, JwsAlgES384, JwsAlgES512:
		return true
	}
	return false
}

// JweAlg represents a key encryption algorithm used for JSON Web Encryption (JWE) and JSON Web Key (JWK) objects
// See https://tools.ietf.org/html/rfc7518#section-4 for more information

const (
	JweAlgDir                string = "dir"
	JweAlgRSA1_5             string = "RSA1_5"
	JweAlgRSA_OAEP           string = "RSA-OAEP"
	JweAlgRSA_OAEP_256       string = "RSA-OAEP-256"
	JweAlgA128KW             string = "A128KW"
	JweAlgA192KW             string = "A192KW"
	JweAlgA256KW             string = "A256KW"
	JweAlgECDH_ES            string = "ECDH-ES"
	JweAlgECDH_ES_A128KW     string = "ECDH-ES+A128KW"
	JweAlgECDH_ES_A192KW     string = "ECDH-ES+A192KW"
	JweAlgECDH_ES_A256KW     string = "ECDH-ES+A256KW"
	JweAlgA128GCMKW          string = "A128GCMKW"
	JweAlgA192GCMKW          string = "A192GCMKW"
	JweAlgA256GCMKW          string = "A256GCMKW"
	JweAlgPBES2_HS256_A128KW string = "PBES2-HS256+A128KW"
	JweAlgPBES2_HS384_A192KW string = "PBES2-HS384+A192KW"
	JweAlgPBES2_HS512_A256KW string = "PBES2-HS512+A256KW"
)

// JweAlg represents a content encryption algorithm used for JSON Web Encryption (JWE) objects
// See https://tools.ietf.org/html/rfc7518#section-5 for more information

const (
	JweEncAlgA128CBC_HS256 string = "A128CBC-HS256"
	JweEncAlgA192CBC_HS384 string = "A192CBC-HS384"
	JweEncAlgA256CBC_HS512 string = "A256CBC-HS512"
	JweEncAlgA128GCM       string = "A128GCM"
	JweEncAlgA192GCM       string = "A192GCM"
	JweEncAlgA256GCM       string = "A256GCM"
)
