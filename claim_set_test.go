package gose

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

var claimSetTestVectors = []struct {
	name  string
	c     *ClaimSet
	cJson []byte
}{
	{
		"Test 1 - Full ClaimSet Set W/ Additional Members",
		&ClaimSet{
			Issuer:             "ISS-VALUE",
			Subject:            "SUB-VALUE",
			Audience:           []string{"AUD1", "AUD2"},
			Id:                 "JTI",
			Expiration:         time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
			NotBefore:          time.Date(2009, time.November, 11, 23, 0, 0, 0, time.UTC),
			IssuedAt:           time.Date(2009, time.November, 12, 23, 0, 0, 0, time.UTC),
			AdditionalClaimSet: map[string]interface{}{"a": 101, "b": []byte("blah")},
		},
		[]byte(`{"a":101,"aud":["AUD1","AUD2"],"b":"YmxhaA==","exp":1257894000,"iat":1258066800,"iss":"ISS-VALUE","jti":"JTI","nbf":1257980400,"sub":"SUB-VALUE"}`),
	},
	{
		"Test 2 - Full ClaimSet Set W/O Additional Members",
		&ClaimSet{
			Issuer:     "ISS-VALUE 2",
			Subject:    "SUB-VALUE 2",
			Audience:   []string{"AUD3", "AUD4"},
			Id:         "JTI 2",
			Expiration: time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
			NotBefore:  time.Date(2009, time.November, 11, 23, 0, 0, 0, time.UTC),
			IssuedAt:   time.Date(2009, time.November, 12, 23, 0, 0, 0, time.UTC),
		},
		[]byte(`{"aud":["AUD3","AUD4"],"exp":1257894000,"iat":1258066800,"iss":"ISS-VALUE 2","jti":"JTI 2","nbf":1257980400,"sub":"SUB-VALUE 2"}`),
	},
}

func BenchmarkClaimSetMarshal(b *testing.B) {
	for n := 0; n < b.N; n++ {
		json.Marshal(claimSetTestVectors[0].c)
	}
}

func BenchmarkClaimSetUnmarshal(b *testing.B) {
	c := new(ClaimSet)
	for n := 0; n < b.N; n++ {
		json.Unmarshal(claimSetTestVectors[0].cJson, c)
	}
}

func TestClaimSetMarshal(t *testing.T) {
	for i, v := range claimSetTestVectors {
		data, err := json.Marshal(v.c)
		if err != nil {
			t.Errorf("Unable to Marshal ClaimSet %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.cJson) {
			t.Errorf("ClaimSet %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.cJson, data)
		}
	}
}

func TestClaimSetUnmarshal(t *testing.T) {
	for i, v := range claimSetTestVectors {
		cTest := new(ClaimSet)
		err := json.Unmarshal(v.cJson, cTest)
		if err != nil {
			t.Errorf("Unable to Unmarshal cJson %d. Err: %v\n", i+1, err)
		}

		data, err := json.Marshal(cTest)
		if err != nil {
			t.Errorf("Unable to Marshal claims Json %d. Err: %v\n", i+1, err)
		}

		if !bytes.Equal(data, v.cJson) {
			t.Errorf("ClaimSet %d. \nExpected:\n%s \nGot:\n%s\n", i+1, v.cJson, data)
		}
	}
}
