package gose

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

var testVectors = []struct {
	time      time.Time
	base64URL []byte
}{
	{
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		[]byte(`1257894000`),
	},
	{
		time.Date(2017, time.May, 25, 0, 1, 2, 0, time.UTC),
		[]byte(`1495670462`),
	},
}

func TestNumericDateUnmarshal(t *testing.T) {
	var nd NumericDate
	for i, v := range testVectors {
		err := json.Unmarshal(v.base64URL, &nd)
		if err != nil {
			t.Errorf("Unable to unmarshal test vector #%d. Err: %v", i+1, err)
		}
		if !nd.Time.Equal(v.time) {
			t.Errorf("Unmarshaled octets don't match. Test vector %d. \nExpected:\n%v \nGot:\n%v\n", i+1, v.time, nd.Time)
		}
	}
}

func TestNumericDateMarshal(t *testing.T) {
	var nd *NumericDate
	for i, v := range testVectors {
		nd = &NumericDate{Time: v.time}
		b64Json, err := json.Marshal(nd)
		if err != nil {
			t.Errorf("Unable to unmarshal test vector #%d. Err: %v", i+1, err)
		}
		if !bytes.Equal(b64Json, v.base64URL) {
			t.Errorf("Mashaled octets don't match. Test vector %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.base64URL, b64Json)
		}
	}
}
