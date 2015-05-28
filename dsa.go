package sshkey

import (
	"crypto"
	"crypto/dsa"
	"math/big"
)

type DSAPublicKey struct {
	pub *dsa.PublicKey
	basePublicKey
}

func (r *DSAPublicKey) GetLength() int {
	return r.pub.P.BitLen()
}

func (r *DSAPublicKey) GetPublic() crypto.PublicKey {
	return r.pub
}

func UnmarshalOpenSSHDSAPublicKey(c []byte, comment string) (*DSAPublicKey, error) {
	var p, q, g, y []byte

	alg, c := decodeByteSlice(c)
	if alg == nil || string(alg) != "ssh-dss" {
		return nil, ErrMalformedKey
	}

	p, c = decodeByteSlice(c)
	if p == nil {
		return nil, ErrMalformedKey
	}

	q, c = decodeByteSlice(c)
	if q == nil {
		return nil, ErrMalformedKey
	}

	g, c = decodeByteSlice(c)
	if g == nil {
		return nil, ErrMalformedKey
	}

	y, c = decodeByteSlice(c)
	if y == nil {
		return nil, ErrMalformedKey
	}

	key := &DSAPublicKey{
		pub: &dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: new(big.Int).SetBytes(p),
				Q: new(big.Int).SetBytes(q),
				G: new(big.Int).SetBytes(g),
			},
			Y: new(big.Int).SetBytes(y),
		},
		basePublicKey: basePublicKey{
			keyType: KEY_DSA,
			comment: comment,
		},
	}
	return key, nil
}
