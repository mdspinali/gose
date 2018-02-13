package gose

import (
	"encoding/json"
	"time"
)

// NumericDate represents a date as a UTC Unix Timestamp as defined in:
// https://tools.ietf.org/html/rfc7519#section-2
type NumericDate struct {
	time.Time
}

// Returns the UTC Timestamp represenation of the time.Time value
func (nd *NumericDate) Encoded() int64 {
	return nd.UTC().Unix()
}

// Decodes a UTC TimeStamp (int64) into a time.Time (NumericDate) type
func (nd *NumericDate) Decode(enc int64) error {
	t := time.Unix(enc, 0)

	nd.Time = t

	return nil
}

// Implements the json.Marshaler interface and JSON encodes the Numeric Date
func (nd *NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(nd.Encoded())
}

// Implements the json.Unmarshaler interface and JSON decodes the Numeric Date
func (nd *NumericDate) UnmarshalJSON(data []byte) error {
	i := int64(0)
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	if err := nd.Decode(i); err != nil {
		return err
	}

	return nil
}
