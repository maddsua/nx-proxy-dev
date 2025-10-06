package nxproxy_test

import (
	"fmt"
	"testing"

	nxproxy "github.com/maddsua/nx-proxy"
)

func TestToken_1(t *testing.T) {

	token, err := nxproxy.NewServerToken()
	if err != nil {
		t.Fatalf("new token: %v", err)
	}

	tokenString := token.String()
	t.Logf("token: %v", tokenString)

	restored, err := nxproxy.ParseServerToken(tokenString)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	if restored.ID != token.ID {
		t.Errorf("token ID; expected: %v; got: %v", token.ID, restored.ID)
	} else if fmt.Sprintf("%v", restored.SecretKey) != fmt.Sprintf("%v", token.SecretKey) {
		t.Errorf("token key; expected: %v; got: %v", token.SecretKey, restored.SecretKey)
	}
}
