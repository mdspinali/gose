package gose

type Jwe struct {
	ProtectedHeader       *JwHeader
	UnprotectedHeader     *JwHeader
	Recipients            []*JweRecipient
	InitializationVector  []byte
	Tag                   []byte
	Message               []byte
	AdditionalAuthData    []byte
	AdditionalMembers     map[string]interface{}
	cipherText            []byte
	contentEncryptionKey  []byte
	b64URLProtHdrCache    []byte
	b64URLIVCache         []byte
	b64URLAADCache        []byte
	b64URLCipherTextCache []byte
}

type JweRecipient struct {
	Header            *JwHeader
	encryptedKey      []byte
	b64URLEncKeyCache []byte
}

func (jwe *Jwe) Encrypt(jwk *Jwk) {

}

func (jwe *Jwe) Decrypt(jwk *Jwk) {

}

func (jwe *Jwe) EncryptMultiple(jwks *JwkSet) {

}

func (jRecip *JweRecipient) Encrypt(jwe *Jwe, jwk *Jwk) {

}

func (jRecip *JweRecipient) Decrypt(jwe *Jwe, jwk *Jwk) {

}
