package gose

import (
	"encoding/json"
	"time"
)

// Represents a JWT Claim Set as specified in https://tools.ietf.org/html/rfc7519
type ClaimSet struct {
	Issuer             string                 `json:"iss,omitempty"`
	Subject            string                 `json:"sub,omitempty"`
	Audience           []string               `json:"aud,omitempty"`
	Id                 string                 `json:"jti,omitempty"`
	Expiration         time.Time              `json:"exp,omitempty"`
	NotBefore          time.Time              `json:"nbf,omitempty"`
	IssuedAt           time.Time              `json:"iat,omitempty"`
	AdditionalClaimSet map[string]interface{} `json:"-"`
}

// Implements the json.Unmarshaler interface and JSON decodes a JSON representation of the a JWT ClaimSet Set.
func (c *ClaimSet) UnmarshalJSON(data []byte) (err error) {
	var obj map[string]json.RawMessage

	// Unmarshal into Map of Json.RawMessages. Each key is the JSON field, each value is the
	// the value of each JSON Field
	err = json.Unmarshal(data, &obj)
	if err != nil {

	}

	// Check if each member of the ClaimSet struct is present in the obj map. If it is,
	// then attempt to unmarshal that member. Then, delete the member from obj
	if v, ok := obj["iss"]; ok {
		err = json.Unmarshal(v, &c.Issuer)
		if err != nil {

		}
		delete(obj, "iss")
	}
	if v, ok := obj["sub"]; ok {
		err = json.Unmarshal(v, &c.Subject)
		if err != nil {

		}
		delete(obj, "sub")
	}
	if v, ok := obj["aud"]; ok {
		err = json.Unmarshal(v, &c.Audience)
		if err != nil {

		}
		delete(obj, "aud")
	}
	if v, ok := obj["jti"]; ok {
		err = json.Unmarshal(v, &c.Id)
		if err != nil {

		}
		delete(obj, "jti")
	}
	if v, ok := obj["exp"]; ok {
		var nd NumericDate
		err = json.Unmarshal(v, &nd)
		if err != nil {

		}
		c.Expiration = nd.Time
		delete(obj, "exp")
	}
	if v, ok := obj["nbf"]; ok {
		var nd NumericDate
		err = json.Unmarshal(v, &nd)
		if err != nil {

		}
		c.NotBefore = nd.Time
		delete(obj, "nbf")
	}
	if v, ok := obj["iat"]; ok {
		var nd NumericDate
		err = json.Unmarshal(v, &nd)
		if err != nil {

		}
		c.IssuedAt = nd.Time
		delete(obj, "iat")
	}

	// Unmarshal remaing JSON k/v pairs into an interface{}
	if len(obj) > 0 {
		// Allocate AdditionalClaimSet member to the be the number of remaining keys in obj
		c.AdditionalClaimSet = make(map[string]interface{}, len(obj))

		for k, v := range obj {
			var intfVal interface{}
			err = json.Unmarshal(v, &intfVal)
			if err != nil {

			}
			c.AdditionalClaimSet[k] = intfVal
		}
	}

	return nil
}

func (c *ClaimSet) MarshalJSON() ([]byte, error) {

	// remove duplicate claims from AdditionalClaimSet
	delete(c.AdditionalClaimSet, "iss")
	delete(c.AdditionalClaimSet, "sub")
	delete(c.AdditionalClaimSet, "aud")
	delete(c.AdditionalClaimSet, "jti")
	delete(c.AdditionalClaimSet, "exp")
	delete(c.AdditionalClaimSet, "nbf")
	delete(c.AdditionalClaimSet, "iat")

	// There are additional claims, individually marshal each member
	obj := make(map[string]*json.RawMessage, len(c.AdditionalClaimSet)+7)

	if len(c.Issuer) > 0 {
		if bytes, err := json.Marshal(c.Issuer); err == nil {
			rm := json.RawMessage(bytes)
			obj["iss"] = &rm
		} else {
			return bytes, err
		}

	}
	if len(c.Subject) > 0 {
		if bytes, err := json.Marshal(c.Subject); err == nil {
			rm := json.RawMessage(bytes)
			obj["sub"] = &rm
		} else {
			return bytes, err
		}
	}
	if len(c.Audience) > 0 {
		if bytes, err := json.Marshal(c.Audience); err == nil {
			rm := json.RawMessage(bytes)
			obj["aud"] = &rm
		} else {
			return bytes, err
		}
	}
	if len(c.Id) > 0 {
		if bytes, err := json.Marshal(c.Id); err == nil {
			rm := json.RawMessage(bytes)
			obj["jti"] = &rm
		} else {
			return bytes, err
		}
	}
	if !(c.Expiration.IsZero()) {
		nd := &NumericDate{c.Expiration}
		if bytes, err := json.Marshal(nd); err == nil {
			rm := json.RawMessage(bytes)
			obj["exp"] = &rm
		} else {
			return bytes, err
		}
	}
	if !(c.NotBefore.IsZero()) {
		nd := &NumericDate{c.NotBefore}
		if bytes, err := json.Marshal(nd); err == nil {
			rm := json.RawMessage(bytes)
			obj["nbf"] = &rm
		} else {
			return bytes, err
		}
	}
	if !(c.IssuedAt.IsZero()) {
		nd := &NumericDate{c.IssuedAt}
		if bytes, err := json.Marshal(nd); err == nil {
			rm := json.RawMessage(bytes)
			obj["iat"] = &rm
		} else {
			return bytes, err
		}
	}

	//Iterate through remaing members and add to json rawMessage
	for k, v := range c.AdditionalClaimSet {
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
