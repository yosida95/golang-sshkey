package sshkey

import (
	"crypto"
	"crypto/rsa"
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

func UnmarshalOpenSSHRSAPublicKey(c []byte, comment string) (*RSAPublicKey, error) {
	var alg, exp, mod []byte

	alg, c = decodeByteSlice(c)
	if alg == nil || string(alg) != "ssh-rsa" {
		return nil, ErrMalformedKey
	}

	exp, c = decodeByteSlice(c)
	if exp == nil {
		return nil, ErrMalformedKey
	}

	mod, _ = decodeByteSlice(c)
	if mod == nil {
		return nil, ErrMalformedKey
	}

	key := &RSAPublicKey{
		pub: &rsa.PublicKey{
			E: int(new(big.Int).SetBytes(exp).Int64()),
			N: new(big.Int).SetBytes(mod),
		},
		basePublicKey: basePublicKey{
			keyType: KEY_RSA,
			comment: comment,
		},
	}
	return key, nil
}
