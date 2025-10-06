package nxproxy

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type ServerToken struct {
	ID        uuid.UUID
	SecretKey []byte
}

func (token *ServerToken) String() string {
	return fmt.Sprintf("%s.%s",
		base64.RawURLEncoding.EncodeToString(token.ID[:]),
		base64.RawURLEncoding.EncodeToString(token.SecretKey))
}

func ParseServerToken(val string) (*ServerToken, error) {

	before, after, has := strings.Cut(val, ".")
	if !has {
		return nil, fmt.Errorf("illformed token string")
	}

	var decodeBase = func(val string) []byte {
		bytes, err := base64.RawURLEncoding.DecodeString(val)
		if err != nil {
			return nil
		}
		return bytes
	}

	tokenID, err := uuid.FromBytes(decodeBase(before))
	if err != nil {
		return nil, fmt.Errorf("illformed token ID: %v", err)
	}

	secretBytes := decodeBase(after)
	if secretBytes == nil {
		return nil, fmt.Errorf("illformed token key")
	}

	return &ServerToken{ID: tokenID, SecretKey: secretBytes}, nil
}

func NewServerToken() (*ServerToken, error) {

	newID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("generate ID: %v", err)
	}

	newSecret := make([]byte, 64)
	if _, err := rand.Reader.Read(newSecret); err != nil {
		return nil, fmt.Errorf("generate key: %v", err)
	}

	return &ServerToken{ID: newID, SecretKey: newSecret}, nil
}
