package proxy

type Authenticator interface {
	LookupWithPassword(username, password string) (*Peer, error)
}
