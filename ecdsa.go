package sshkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
)

type ECDSAPublicKey struct {
	pub *ecdsa.PublicKey
	basePublicKey
}

func (k *ECDSAPublicKey) GetLength() int {
	return k.pub.Curve.Params().BitSize
}

func (k *ECDSAPublicKey) GetPublic() crypto.PublicKey {
	return k.pub
}

func unmarshalOpenSSHECDSAPublicKey(c []byte, comment string) (*ECDSAPublicKey, error) {
	var alg, cName, data []byte

	alg, c = decodeByteSlice(c)
	if alg == nil || !bytes.HasPrefix(alg, []byte("ecdsa-sha2-")) {
		return nil, ErrMalformedKey
	}

	cName, c = decodeByteSlice(c)
	if cName == nil {
		return nil, ErrMalformedKey
	}

	data, c = decodeByteSlice(c)
	if data == nil {
		return nil, ErrMalformedKey
	}

	var curve elliptic.Curve
	switch string(cName) {
	case "nistp256":
		curve = elliptic.P256()
	case "nistp384":
		curve = elliptic.P384()
	case "nistp521":
		curve = elliptic.P521()
	default:
		return nil, ErrUnsupportedKey
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
	}
	pub.X, pub.Y = elliptic.Unmarshal(curve, data)
	if pub.X == nil {
		return nil, ErrUnsupportedKey
	}

	key := &ECDSAPublicKey{
		pub: pub,
		basePublicKey: basePublicKey{
			keyType: KEY_ECDSA,
			comment: comment,
		},
	}
	return key, nil
}
