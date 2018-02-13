package gose

import (
//"encoding/json"
//"fmt"
)

// Alg represents a Signautre algorithm, Content Encryption or Key Encryption Algorithm.
// TODO(intf): Make Alg an Interface.
// See https://tools.ietf.org/html/rfc7518 for more information
type Jwa string

func (alg Jwa) GetJwkType() JwkType {
	switch alg {
	case JwsAlgRS256, JwsAlgRS384, JwsAlgRS512, JwsAlgPS256, JwsAlgPS384, JwsAlgPS512, JweAlgRSA1_5,
		JweAlgRSA_OAEP, JweAlgRSA_OAEP_256:
		return JwkTypeRSA
	case JweAlgDir, JweAlgA128KW, JweAlgA128GCMKW, JweAlgA192KW, JweAlgA192GCMKW, JweAlgA256KW,
		JweAlgA256GCMKW, JweAlgPBES2_HS256_A128KW, JweAlgPBES2_HS384_A192KW,
		JweAlgPBES2_HS512_A256KW, JwsAlgHS256, JwsAlgHS384, JwsAlgHS512:
		return JwkTypeOct
	case JweAlgECDH_ES, JweAlgECDH_ES_A128KW, JweAlgECDH_ES_A192KW, JweAlgECDH_ES_A256KW, JwsAlgES256,
		JwsAlgES384, JwsAlgES512:
		return JwkTypeEC
	}

	return ""
}

// JwsAlg represents a signature algorithm used for JSON Web Signatures (JWS).
// See https://tools.ietf.org/html/rfc7518#section-3 for more information
const (
	JwsAlgHS256 Jwa = "HS256"
	JwsAlgHS384 Jwa = "HS384"
	JwsAlgHS512 Jwa = "HS512"
	JwsAlgRS256 Jwa = "RS256"
	JwsAlgRS384 Jwa = "RS384"
	JwsAlgRS512 Jwa = "RS512"
	JwsAlgES256 Jwa = "ES256"
	JwsAlgES384 Jwa = "ES384"
	JwsAlgES512 Jwa = "ES512"
	JwsAlgPS256 Jwa = "PS256"
	JwsAlgPS384 Jwa = "PS384"
	JwsAlgPS512 Jwa = "PS512"
	JwsAlgNone  Jwa = "none"
)

func (alg Jwa) IsValidJwsAlg() bool {
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
	JweAlgDir                Jwa = "dir"
	JweAlgRSA1_5             Jwa = "RSA1_5"
	JweAlgRSA_OAEP           Jwa = "RSA-OAEP"
	JweAlgRSA_OAEP_256       Jwa = "RSA-OAEP-256"
	JweAlgA128KW             Jwa = "A128KW"
	JweAlgA192KW             Jwa = "A192KW"
	JweAlgA256KW             Jwa = "A256KW"
	JweAlgECDH_ES            Jwa = "ECDH-ES"
	JweAlgECDH_ES_A128KW     Jwa = "ECDH-ES+A128KW"
	JweAlgECDH_ES_A192KW     Jwa = "ECDH-ES+A192KW"
	JweAlgECDH_ES_A256KW     Jwa = "ECDH-ES+A256KW"
	JweAlgA128GCMKW          Jwa = "A128GCMKW"
	JweAlgA192GCMKW          Jwa = "A192GCMKW"
	JweAlgA256GCMKW          Jwa = "A256GCMKW"
	JweAlgPBES2_HS256_A128KW Jwa = "PBES2-HS256+A128KW"
	JweAlgPBES2_HS384_A192KW Jwa = "PBES2-HS384+A192KW"
	JweAlgPBES2_HS512_A256KW Jwa = "PBES2-HS512+A256KW"
)

// JweAlg represents a content encryption algorithm used for JSON Web Encryption (JWE) objects
// See https://tools.ietf.org/html/rfc7518#section-5 for more information

const (
	JweEncAlgA128CBC_HS256 Jwa = "A128CBC-HS256"
	JweEncAlgA192CBC_HS384 Jwa = "A192CBC-HS384"
	JweEncAlgA256CBC_HS512 Jwa = "A256CBC-HS512"
	JweEncAlgA128GCM       Jwa = "A128GCM"
	JweEncAlgA192GCM       Jwa = "A192GCM"
	JweEncAlgA256GCM       Jwa = "A256GCM"
)
