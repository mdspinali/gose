package gose

import (
	"encoding/json"
)

// The JSON Web header used by JWE and JWS
type JwHeader struct {
	Algorithm            string
	EncryptionAlg        string
	Compression          string
	JwkUrl               string
	Jwk                  *Jwk
	KeyId                string
	Type                 string
	ContentType          string
	AgreePartyUInfo      []byte
	AgreePartyVInfo      []byte
	EphermalPubKey       *Jwk
	Critical             []string
	X509Url              string
	X509CertChain        [][]byte
	X509Thumbprint       []byte
	X509Sha256Thumbprint []byte
	AdditionalMembers    map[string]interface{}
}

func (h *JwHeader) UnmarshalJSON(data []byte) error {
	var obj map[string]json.RawMessage

	// Unmarshal into Map of Json.RawMessages. Each key is the JSON field, each value is the
	// the value of each JSON Field
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return err
	}

	// Check if each member of the Claims struct is present in the obj map. If it is,
	// then attempt to unmarshal that member. Then, delete the member from obj
	if v, ok := obj["alg"]; ok {
		err = json.Unmarshal(v, &h.Algorithm)
		if err != nil {
			return err
		}
		delete(obj, "alg")
	}
	if v, ok := obj["enc"]; ok {
		err = json.Unmarshal(v, &h.EncryptionAlg)
		if err != nil {
			return err
		}
		delete(obj, "enc")
	}
	if v, ok := obj["zip"]; ok {
		err = json.Unmarshal(v, &h.Compression)
		if err != nil {
			return err
		}
		delete(obj, "zip")
	}
	if v, ok := obj["jku"]; ok {
		err = json.Unmarshal(v, &h.JwkUrl)
		if err != nil {
			return err
		}
		delete(obj, "jku")
	}
	if v, ok := obj["jwk"]; ok {
		err = json.Unmarshal(v, &h.Jwk)
		if err != nil {
			return err
		}
		delete(obj, "jwk")
	}
	if v, ok := obj["kid"]; ok {
		err = json.Unmarshal(v, &h.KeyId)
		if err != nil {
			return err
		}
		delete(obj, "kid")
	}
	if v, ok := obj["typ"]; ok {
		err = json.Unmarshal(v, &h.Type)
		if err != nil {
			return err
		}
		delete(obj, "typ")
	}
	if v, ok := obj["cty"]; ok {
		err = json.Unmarshal(v, &h.ContentType)
		if err != nil {
			return err
		}
		delete(obj, "cty")
	}
	if v, ok := obj["apu"]; ok {
		b64o := Base64UrlOctets{}
		err = json.Unmarshal(v, &b64o)
		if err != nil {
			return err
		}
		h.AgreePartyUInfo = b64o.Octets
		delete(obj, "apu")
	}
	if v, ok := obj["apv"]; ok {
		b64o := Base64UrlOctets{}
		err = json.Unmarshal(v, &b64o)
		if err != nil {
			return err
		}
		h.AgreePartyVInfo = b64o.Octets
		delete(obj, "apv")
	}
	if v, ok := obj["epk"]; ok {
		err = json.Unmarshal(v, &h.EphermalPubKey)
		if err != nil {
			return err
		}
		delete(obj, "epk")
	}
	if v, ok := obj["crit"]; ok {
		err = json.Unmarshal(v, &h.Critical)
		if err != nil {
			return err
		}
		delete(obj, "crit")
	}
	if v, ok := obj["x5u"]; ok {
		err = json.Unmarshal(v, &h.X509Url)
		if err != nil {
			return err
		}
		delete(obj, "x5u")
	}
	if v, ok := obj["x5c"]; ok {
		err = json.Unmarshal(v, &h.X509CertChain)
		if err != nil {
			return err
		}
		delete(obj, "x5c")
	}
	if v, ok := obj["x5t"]; ok {
		b64o := Base64UrlOctets{}
		err = json.Unmarshal(v, &b64o)
		if err != nil {
			return err
		}
		h.X509Thumbprint = b64o.Octets
		delete(obj, "x5t")
	}
	if v, ok := obj["x5t#S256"]; ok {
		b64o := Base64UrlOctets{}
		err = json.Unmarshal(v, &b64o)
		if err != nil {
			return err
		}
		h.X509Sha256Thumbprint = b64o.Octets
		delete(obj, "x5t#S256")
	}

	// Unmarshal remaing JSON k/v pairs into an interface{}
	if len(obj) > 0 {
		// Allocate AdditionalClaims member to the be the number of remaining keys in obj
		h.AdditionalMembers = make(map[string]interface{}, len(obj))

		for k, v := range obj {
			var intfVal interface{}
			err = json.Unmarshal(v, &intfVal)
			if err != nil {
				return err
			}
			h.AdditionalMembers[k] = intfVal
		}
	}

	return nil
}

func (h *JwHeader) MarshalJSON() ([]byte, error) {
	// Remove any potentionally conflicting claims from the JWK's additional members
	delete(h.AdditionalMembers, "alg")
	delete(h.AdditionalMembers, "enc")
	delete(h.AdditionalMembers, "zip")
	delete(h.AdditionalMembers, "jku")
	delete(h.AdditionalMembers, "jwk")
	delete(h.AdditionalMembers, "kid")
	delete(h.AdditionalMembers, "typ")
	delete(h.AdditionalMembers, "cty")
	delete(h.AdditionalMembers, "apu")
	delete(h.AdditionalMembers, "apv")
	delete(h.AdditionalMembers, "epk")
	delete(h.AdditionalMembers, "crit")
	delete(h.AdditionalMembers, "x5u")
	delete(h.AdditionalMembers, "x5c")
	delete(h.AdditionalMembers, "x5t")
	delete(h.AdditionalMembers, "x5t#S256")

	// Individually marshal each member
	obj := make(map[string]*json.RawMessage, len(h.AdditionalMembers)+7)

	if len(h.Algorithm) > 0 {
		if bytes, err := json.Marshal(h.Algorithm); err == nil {
			rm := json.RawMessage(bytes)
			obj["alg"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.EncryptionAlg) > 0 {
		if bytes, err := json.Marshal(h.EncryptionAlg); err == nil {
			rm := json.RawMessage(bytes)
			obj["enc"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.Compression) > 0 {
		if bytes, err := json.Marshal(h.Compression); err == nil {
			rm := json.RawMessage(bytes)
			obj["zip"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.JwkUrl) > 0 {
		if bytes, err := json.Marshal(h.JwkUrl); err == nil {
			rm := json.RawMessage(bytes)
			obj["jku"] = &rm
		} else {
			return nil, err
		}
	}
	if h.Jwk != nil {
		if bytes, err := json.Marshal(h.Jwk); err == nil {
			rm := json.RawMessage(bytes)
			obj["jwk"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.KeyId) > 0 {
		if bytes, err := json.Marshal(h.KeyId); err == nil {
			rm := json.RawMessage(bytes)
			obj["kid"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.Type) > 0 {
		if bytes, err := json.Marshal(h.Type); err == nil {
			rm := json.RawMessage(bytes)
			obj["typ"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.ContentType) > 0 {
		if bytes, err := json.Marshal(h.ContentType); err == nil {
			rm := json.RawMessage(bytes)
			obj["cty"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.AgreePartyUInfo) > 0 {
		b64o := &Base64UrlOctets{Octets: h.AgreePartyUInfo}
		if bytes, err := json.Marshal(b64o); err == nil {
			rm := json.RawMessage(bytes)
			obj["apu"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.AgreePartyVInfo) > 0 {
		b64o := &Base64UrlOctets{Octets: h.AgreePartyVInfo}
		if bytes, err := json.Marshal(b64o); err == nil {
			rm := json.RawMessage(bytes)
			obj["apv"] = &rm
		} else {
			return nil, err
		}
	}
	if h.EphermalPubKey != nil {
		if bytes, err := json.Marshal(h.EphermalPubKey); err == nil {
			rm := json.RawMessage(bytes)
			obj["epk"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.Critical) > 0 {
		if bytes, err := json.Marshal(h.Critical); err == nil {
			rm := json.RawMessage(bytes)
			obj["crit"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.X509Url) > 0 {
		if bytes, err := json.Marshal(h.X509Url); err == nil {
			rm := json.RawMessage(bytes)
			obj["x5u"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.X509CertChain) > 0 {
		if bytes, err := json.Marshal(h.X509CertChain); err == nil {
			rm := json.RawMessage(bytes)
			obj["x5c"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.X509Thumbprint) > 0 {
		b64o := &Base64UrlOctets{Octets: h.X509Thumbprint}
		if bytes, err := json.Marshal(b64o); err == nil {
			rm := json.RawMessage(bytes)
			obj["x5t"] = &rm
		} else {
			return nil, err
		}
	}
	if len(h.X509Sha256Thumbprint) > 0 {
		b64o := &Base64UrlOctets{Octets: h.X509Sha256Thumbprint}
		if bytes, err := json.Marshal(b64o); err == nil {
			rm := json.RawMessage(bytes)
			obj["x5t#S256"] = &rm
		} else {
			return nil, err
		}
	}

	//Iterate through remaing members and add to json rawMessage
	for k, v := range h.AdditionalMembers {
		if bytes, err := json.Marshal(v); err == nil {
			rm := json.RawMessage(bytes)
			obj[k] = &rm
		} else {
			return bytes, err
		}
	}

	// Marshal obj
	return json.Marshal(obj)
}
