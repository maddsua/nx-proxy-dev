package main

import "net"

type InstanceLock interface {
	Unlock() error
}

func NewInstanceLock() (InstanceLock, error) {

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "@nxproxy-instance-lock", Net: "unix"})
	if err != nil {
		return nil, err
	}

	return &unixInstanceLocker{UnixListener: listener}, nil
}

type unixInstanceLocker struct {
	*net.UnixListener
}

func (lock *unixInstanceLocker) Unlock() error {
	return lock.Close()
}
