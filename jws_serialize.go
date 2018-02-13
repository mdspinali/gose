package gose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	//"fmt"
	"strings"
)

func (jws *Jws) UnmarshalJSON(data []byte) error {
	var obj map[string]json.RawMessage

	// Unmarshal into Map of Json.RawMessages. Each key is the JSON field, each value is the
	// the value of each JSON Field
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return err
	}

	if v, ok := obj["payload"]; ok {
		b64o := Base64UrlOctets{}
		err = json.Unmarshal(v, &b64o)
		if err != nil {
			return err
		}
		jws.Payload = b64o.Octets
		// Cache the Base64URL-encoded payload as this will be used for signature verification
		// Remove ending quotes from the JSON value
		b64PayloadStr := string(v)
		jws.b64URLPayloadCache = []byte(strings.Trim(b64PayloadStr, "\""))
		delete(obj, "payload")
	}

	// Determine if flattened or General syntax by checking to see if signatures or signature is present
	if v, ok := obj["signatures"]; ok {
		jws.JSONSerialization = JSONSerializationGeneral
		err = json.Unmarshal(v, &jws.Signatures)
		if err != nil {
			return err
		}
	} else if _, ok := obj["signature"]; ok {
		jws.JSONSerialization = JSONSerializationFlat

		// Initialize Signatures to one item
		jws.Signatures = make([]*JwsSignature, 1)

		err = json.Unmarshal(data, &jws.Signatures[0])
		if err != nil {
			return err
		}

		delete(obj, "signature")
		delete(obj, "protected")
		delete(obj, "header")
	}

	// Put any additional members are members in the incorrect syntax, in the additional
	// members map
	if len(obj) > 0 {
		// Allocate AdditionalClaims member to the be the number of remaining keys in obj
		jws.AdditionalMembers = make(map[string]interface{}, len(obj))

		for k, v := range obj {
			var intfVal interface{}
			err = json.Unmarshal(v, &intfVal)
			if err != nil {

			}
			jws.AdditionalMembers[k] = intfVal
		}
	}

	return nil
}

func (jws *Jws) MarshalJSON() ([]byte, error) {
	// Allocate map of JSON Field Keys to JSON.RawMessages to maximum # of possible k/v pairs. The max
	// is equal to the # of keys from the flattened syntax + the # of items in jws.AdditionalMembers
	obj := make(map[string]*json.RawMessage, 4+len(jws.AdditionalMembers))

	if len(jws.Payload) > 0 {
		b64o := &Base64UrlOctets{Octets: jws.Payload}
		if bytes, err := json.Marshal(b64o); err == nil {
			rm := json.RawMessage(bytes)
			obj["payload"] = &rm
		} else {
			return nil, err
		}
	}

	// By default, General serialization will be used
	if jws.JSONSerialization == JSONSerializationFlat {
		if len(jws.Signatures) > 0 {
			jSig := jws.Signatures[0]

			if jSig.ProtectedHeader != nil {
				if protJson, err := json.Marshal(jSig.ProtectedHeader); err == nil {
					b64o := &Base64UrlOctets{Octets: protJson}
					if bytes, err := json.Marshal(b64o); err == nil {
						rm := json.RawMessage(bytes)
						obj["protected"] = &rm
					} else {
						return nil, err
					}
				} else {
					return nil, err
				}
			}
			if jSig.UnprotectedHeader != nil {
				if bytes, err := json.Marshal(jSig.UnprotectedHeader); err == nil {
					rm := json.RawMessage(bytes)
					obj["header"] = &rm
				} else {
					return nil, err
				}
			}
			if len(jSig.signature) > 0 {
				b64o := &Base64UrlOctets{Octets: jSig.signature}
				if bytes, err := json.Marshal(b64o); err == nil {
					rm := json.RawMessage(bytes)
					obj["signature"] = &rm
				} else {
					return nil, err
				}
			}
		}
	} else {
		if bytes, err := json.Marshal(jws.Signatures); err == nil {
			rm := json.RawMessage(bytes)
			obj["signatures"] = &rm
		} else {
			return nil, err
		}
	}

	//Iterate through remaing members and add to json.RawMessage map
	for k, v := range jws.AdditionalMembers {
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

func (jws *Jws) UnmarshalCompact(data []byte) error {
	// Convert byte array to string and trim starting/ending whitespace
	jStr := strings.TrimSpace(string(data))

	// Split the string by the dots ".". Even with an unsercured JWT, there should be exactly 3 elements
	jSplit := strings.Split(jStr, ".")
	if len(jSplit) != 3 {
		return errors.New("Invalid Compact JWS. The number of jws segments must be exactly 3")
	}

	// Parse Payload
	payload, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(jSplit[1])
	if err != nil {
		return err
	}
	jws.b64URLPayloadCache = []byte(jSplit[1])

	// Parse Protected Header and signature
	pHdr := new(JwHeader)
	pHdrJson, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(jSplit[0])
	if err != nil {
		return err
	} else if err := pHdr.UnmarshalJSON(pHdrJson); err != nil {
		return err
	}

	sig, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(jSplit[2])
	if err != nil {
		return err
	}

	// Create signature object
	jSig := new(JwsSignature)
	jSig.ProtectedHeader = pHdr
	jSig.signature = sig
	jSig.b64URLProtHdrCache = []byte(jSplit[0])

	// Set fields for JWS object
	jws.Payload = payload
	jws.Signatures = []*JwsSignature{jSig}

	return nil
}

func (jws *Jws) MarshalCompact() ([]byte, error) {
	// Obtain the last signature object
	if len(jws.Signatures) > 1 {
		return nil, errors.New("Only one signature is supported with JWS Compact serialization")
	} else if len(jws.Signatures) < 1 {
		return nil, errors.New("The JWS must have at least one signature")
	}

	jSig := jws.Signatures[0]

	// Export the header to Json and then B64 Encode.
	pHdrJson, err := jSig.ProtectedHeader.MarshalJSON()
	if err != nil {
		return nil, err
	}
	pHdr := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(pHdrJson)
	payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(jws.Payload)
	sigB64 := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(jSig.signature)

	// Append separation dot ".", b64 URL encoded body,
	// the separation dot "." and the signature value
	out := make([]byte, len(pHdr)+len(payload)+len(sigB64)+2)
	copy(out[:len(pHdr)], pHdr)
	copy(out[len(pHdr):], ".")
	copy(out[len(pHdr)+1:], payload)
	copy(out[len(pHdr)+1+len(payload):], ".")
	copy(out[len(pHdr)+len(payload)+2:], sigB64)

	return out, nil
}

func (jSig *JwsSignature) UnmarshalJSON(data []byte) error {
	var obj map[string]json.RawMessage

	// Unmarshal into Map of Json.RawMessages. Each key is the JSON field, each value is the
	// the value of each JSON Field
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return err
	}

	if v, ok := obj["protected"]; ok {
		b64o := Base64UrlOctets{}
		err = json.Unmarshal(v, &b64o)
		if err != nil {
			return err
		}

		// Cache the Base64URL-encoded protected header as this will be used for signature verification
		// Remove ending quotes from the JSON value
		b64PayloadStr := string(v)
		jSig.b64URLProtHdrCache = []byte(strings.Trim(b64PayloadStr, "\""))

		err = json.Unmarshal(b64o.Octets, &jSig.ProtectedHeader)
		if err != nil {
			return err
		}
	}
	if v, ok := obj["header"]; ok {
		err = json.Unmarshal(v, &jSig.UnprotectedHeader)
		if err != nil {
			return err
		}
	}
	if v, ok := obj["signature"]; ok {
		b64o := Base64UrlOctets{}
		err = json.Unmarshal(v, &b64o)
		if err != nil {
			return err
		}
		jSig.signature = b64o.Octets

	}

	return nil
}

func (jSig *JwsSignature) MarshalJSON() ([]byte, error) {
	// There are additional claims, individually marshal each member
	obj := make(map[string]*json.RawMessage, 3)

	if jSig.ProtectedHeader != nil {
		if protJson, err := json.Marshal(jSig.ProtectedHeader); err == nil {
			b64o := &Base64UrlOctets{Octets: protJson}
			if bytes, err := json.Marshal(b64o); err == nil {
				rm := json.RawMessage(bytes)
				obj["protected"] = &rm
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if jSig.UnprotectedHeader != nil {
		if bytes, err := json.Marshal(jSig.UnprotectedHeader); err == nil {
			rm := json.RawMessage(bytes)
			obj["header"] = &rm
		} else {
			return nil, err
		}
	}
	if len(jSig.signature) > 0 {
		b64o := &Base64UrlOctets{Octets: jSig.signature}
		if bytes, err := json.Marshal(b64o); err == nil {
			rm := json.RawMessage(bytes)
			obj["signature"] = &rm
		} else {
			return nil, err
		}
	}

	// Marshal obj
	return json.Marshal(obj)
}
