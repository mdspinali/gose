package gose

import (
	"encoding/json"
	"strings"
)

// JwkSet Represents a set of JWK's as defined in https://tools.ietf.org/html/rfc7517#section-5
type JwkSet struct {
	Keys              []*Jwk                 `json:"keys"`
	AdditionalMembers map[string]interface{} `json:"-"`
}

// GetKeyByIdAndType gets a JWK containeed in the JwkSet that is of type typ and has a Key Id of id.
// This function is useful for keys of different types that may have the same key id.
// The desired JWk and whethere or not the JWK exists (boolean) is returned
// https://tools.ietf.org/html/rfc7517#section-4.5
func (jwks *JwkSet) GetKeyByIdAndType(id string, typ JwkType) *Jwk {
	for _, v := range jwks.Keys {
		if v.Type == typ {
			// Remove whitespace and do case-sensitive match. Jwk spec specifies Key ID to be
			// case sensitive
			if strings.TrimSpace(v.Id) == strings.TrimSpace(id) {
				return v
			}
		}
	}

	return nil
}

// GetKeyBId returns the first JWK found with the desired key id. A boolean is also returned
// that signals whether or not a JWK was found
func (jwks *JwkSet) GetKeyById(id string) *Jwk {
	for _, v := range jwks.Keys {
		// Remove whitespace and do case-sensitive match. Jwk spec specifies Key ID to be
		// case sensitive
		if strings.TrimSpace(v.Id) == strings.TrimSpace(id) {
			return v
		}
	}

	return nil
}

// Implements the json.Unmarshaler interface and JSON decodes a JSON representation of the JWK Key Set.
func (jwks *JwkSet) UnmarshalJSON(data []byte) error {

	var obj map[string]json.RawMessage

	// Unmarshal into Map of Json.RawMessages. Each key is the JSON field, each value is the
	// the value of each JSON Field
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return err
	}

	// Check if there are JWK's contained in this JWK set. If there are, unmarshal them
	if v, ok := obj["keys"]; ok {
		err = json.Unmarshal(v, jwks.Keys)
		if err != nil {
			return err
		}
		delete(obj, "keys")
	}

	// Unmarshal remaing JSON k/v pairs into an interface{}
	if len(obj) > 0 {
		// Allocate AdditionalClaims member to the be the number of remaining keys in obj
		jwks.AdditionalMembers = make(map[string]interface{}, len(obj))

		for k, v := range obj {
			var intfVal interface{}
			err = json.Unmarshal(v, &intfVal)
			if err != nil {
				return err
			}
			jwks.AdditionalMembers[k] = intfVal
		}
	}
	return nil
}

// Implements the json.Marshaler interface and JSON encodes the Jwk Key Set
func (jwks *JwkSet) MarshalJSON() ([]byte, error) {
	delete(jwks.AdditionalMembers, "keys")

	obj := make(map[string]*json.RawMessage, len(jwks.AdditionalMembers)+1)

	if len(jwks.Keys) > 0 {
		if bytes, err := json.Marshal(jwks.Keys); err == nil {
			rm := json.RawMessage(bytes)
			obj["keys"] = &rm
		} else {
			return nil, err
		}
	}

	//Iterate through remaing members and add to json rawMessage
	for k, v := range jwks.AdditionalMembers {
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
