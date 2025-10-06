package nxproxy

type Authenticator interface {
	LookupWithPassword(username, password string) (*Peer, error)
}
