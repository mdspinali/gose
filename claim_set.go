package gose

import (
	"encoding/json"
	"time"
	"fmt"
	"strings"
	"errors"
	"reflect"
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
	AdditionalClaims map[string]interface{} `json:"-"`
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
		// Allocate AdditionalClaims member to the be the number of remaining keys in obj
		c.AdditionalClaims = make(map[string]interface{}, len(obj))

		for k, v := range obj {
			var intfVal interface{}
			err = json.Unmarshal(v, &intfVal)
			if err != nil {

			}
			c.AdditionalClaims[k] = intfVal
		}
	}

	return nil
}

func (c *ClaimSet) MarshalJSON() ([]byte, error) {

	// remove duplicate claims from AdditionalClaims
	delete(c.AdditionalClaims, "iss")
	delete(c.AdditionalClaims, "sub")
	delete(c.AdditionalClaims, "aud")
	delete(c.AdditionalClaims, "jti")
	delete(c.AdditionalClaims, "exp")
	delete(c.AdditionalClaims, "nbf")
	delete(c.AdditionalClaims, "iat")

	// There are additional claims, individually marshal each member
	obj := make(map[string]*json.RawMessage, len(c.AdditionalClaims)+7)

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
	for k, v := range c.AdditionalClaims {
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

func (c *ClaimSet) Validate(ref *ClaimSet) error {

	errStrings := make([]string, 0, 6)

	// Only valid the claims that are specified in the reference claimset
	if !ref.Expiration.IsZero() {
		if err := c.ValidateExp(); err != nil {
			errStr := fmt.Sprintf("[Exp]- Validation failed: %s", err.Error())
			errStrings = append(errStrings, errStr)
		}
	}

	if !ref.NotBefore.IsZero() {
		if err := c.ValidateNbf(); err != nil {
			errStr := fmt.Sprintf("[Nbf]- Validation failed: %s", err.Error())
			errStrings = append(errStrings, errStr)
		}
	}

	if ref.Issuer != "" {
		if err := c.ValidateIss(ref.Issuer); err != nil {
			errStr := fmt.Sprintf("[Iss]- Validation failed: %s", err.Error())
			errStrings = append(errStrings, errStr)
		}
	}

	if ref.Subject != "" {
		if err := c.ValidateSub(ref.Subject); err != nil {
			errStr := fmt.Sprintf("[Sub]- Validation failed: %s", err.Error())
			errStrings = append(errStrings, errStr)
		}
	}

	if ref.Audience != nil {
		if err := c.ValidateAud(ref.Audience); err != nil {
			errStr := fmt.Sprintf("[Aud]- Validation failed: %s", err.Error())
			errStrings = append(errStrings, errStr)
		}
	}

	if ref.Id != "" {
		if err := c.ValidateJti(ref.Id); err != nil {
			errStr := fmt.Sprintf("[JTI]- Validation failed: %s", err.Error())
			errStrings = append(errStrings, errStr)
		}
	}

	if ref.AdditionalClaims != nil {
		if err := c.ValidateAdditionalClaims(ref.AdditionalClaims); err != nil {
			errStr := fmt.Sprintf("[Additional Claims]- Validation failed: %s", err.Error())
			errStrings = append(errStrings, errStr)
		}
	}

	return fmt.Errorf(strings.Join(errStrings, "\n"))
}

func (c *ClaimSet) ValidateIss(iss string) error {
	if strings.TrimSpace(c.Issuer) != strings.TrimSpace(iss) {
		return fmt.Errorf("Issuer (%v) doesn't match ref (%v)", c.Issuer, iss)
	}

	return nil
}

func (c *ClaimSet) ValidateSub(sub string) error {
	if strings.TrimSpace(c.Subject) != strings.TrimSpace(sub) {
		return fmt.Errorf("Subject (%s) doesn't match ref (%s)", c.Subject, sub)
	}

	return nil
}

func (c *ClaimSet) ValidateAud(aud []string) error {
	audMap := make(map[string]string)
	for _, v := range c.Audience {
		audMap[strings.TrimSpace(v)] = ""
	}
	for _, rv := range aud {
		v, ok := audMap[strings.TrimSpace(rv)]
		if !ok {
			return fmt.Errorf("Aud Value: %v, doesn't exist in claimset", rv)
		} else if v != rv {
			return fmt.Errorf("Aud Value: %v, doesn't match reference AUD value: %v", v, rv)
		}
	}

	return nil
}

func (c *ClaimSet) ValidateExp() error {
	if c.Expiration.Before(time.Now().UTC()) {
		return errors.New("JWT has expired")
	}

	return nil
}

func (c *ClaimSet) ValidateNbf() error {
	if time.Now().UTC().Before(c.NotBefore) {
		return errors.New("JWT can not yet be accepted for processing")
	}

	return nil
}

func (c *ClaimSet) ValidateJti(jti string) error {
	if strings.TrimSpace(c.Id) != strings.TrimSpace(jti) {
		return fmt.Errorf("Audience (%s) doesn't match ref (%s)", c.Id, jti)
	}

	return nil
}

func (c *ClaimSet) ValidateAdditionalClaims(addlC map[string]interface{}) error {
	for rk, rv := range addlC {
		v, ok := c.AdditionalClaims[rk]
		if !ok {
			return fmt.Errorf("Key: %v, doesnt exist in claimset", rk)
		} else if !reflect.DeepEqual(rv, v) {
			return fmt.Errorf("Reference Key: %v with value: %v, doesnt match corresponding claim value: %v", rk, rv, v)
		}
	}
	return nil
}
