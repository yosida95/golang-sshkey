package sshkey

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrMalformedKey   = errors.New("Malformed key")
	ErrUnsupportedKey = errors.New("Unsupported key")
)

func decodeByteSlice(in []byte) ([]byte, []byte) {
	l := len(in)
	if l < 4 {
		return nil, in
	}

	stop := 4 + int(binary.BigEndian.Uint32(in))
	if l < stop {
		return nil, in
	}

	return in[4:stop], in[stop:l]
}

func UnmarshalOpenSSHPublicKey(pub string) (PublicKey, error) {
	splited := strings.SplitN(pub, " ", 3)
	if len(splited) < 2 {
		return nil, ErrMalformedKey
	}

	var (
		alg     = strings.TrimSpace(splited[0])
		cb64    = strings.TrimSpace(splited[1])
		comment string
	)
	if len(splited) == 3 {
		comment = strings.TrimSpace(splited[2])
	}

	c, err := base64.StdEncoding.DecodeString(cb64)
	if err != nil {
		return nil, err
	}

	switch alg {
	case "ssh-rsa":
		return unmarshalOpenSSHRSAPublicKey(c, comment)
	case "ssh-dss":
		return unmarshalOpenSSHDSAPublicKey(c, comment)
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return unmarshalOpenSSHECDSAPublicKey(c, comment)
	}
	return nil, ErrUnsupportedKey
}
