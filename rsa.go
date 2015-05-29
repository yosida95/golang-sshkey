package sshkey

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
)

type RSAPublicKey struct {
	pub *rsa.PublicKey
	basePublicKey
}

func (r *RSAPublicKey) GetLength() int {
	return r.pub.N.BitLen()
}

func (r *RSAPublicKey) GetPublic() crypto.PublicKey {
	return r.pub
}

func unmarshalOpenSSHRSAPublicKey(c []byte, comment string) (*RSAPublicKey, error) {
	var alg, exp, mod []byte

	alg, c = decodeByteSlice(c)
	if alg == nil || string(alg) != "ssh-rsa" {
		return nil, ErrMalformedKey
	}

	exp, c = decodeByteSlice(c)
	if exp == nil {
		return nil, ErrMalformedKey
	}
	if len(exp) < 4 {
		newExp := make([]byte, 4)
		copy(newExp[4-len(exp):4], exp)
		exp = newExp
	}

	mod, _ = decodeByteSlice(c)
	if mod == nil {
		return nil, ErrMalformedKey
	}

	key := &RSAPublicKey{
		pub: &rsa.PublicKey{
			E: int(binary.BigEndian.Uint32(exp)),
			N: new(big.Int).SetBytes(mod),
		},
		basePublicKey: basePublicKey{
			keyType: KEY_RSA,
			comment: comment,
		},
	}
	return key, nil
}
