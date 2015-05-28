package sshkey

import (
	"crypto"
)

type Type int

const (
	KEY_RSA Type = iota
	KEY_DSA
	KEY_ECDSA
)

type PublicKey interface {
	GetType() Type
	GetPublic() crypto.PublicKey
	GetLength() int
	GetComment() string
}

type basePublicKey struct {
	keyType Type
	comment string
}

func (k *basePublicKey) GetType() Type {
	return k.keyType
}

func (k *basePublicKey) GetComment() string {
	return k.comment
}
