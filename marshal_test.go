package sshkey

import (
	"io/ioutil"
	"strings"
	"testing"
)

var (
	marshalOpenSSHPublicKeyCases = []string{
		"testdata/rsa.pub",
		"testdata/dsa.pub",
		"testdata/ecdsa.pub",
	}
)

func TestMarshalOpenSSHPublicKey(t *testing.T) {
	for _, c := range marshalOpenSSHPublicKeyCases {
		keyB, err := ioutil.ReadFile(c)
		if err != nil {
			panic(err)
		}
		key := strings.TrimSpace(string(keyB))

		pub, err := UnmarshalOpenSSHPublicKey(key)
		if err != nil {
			panic(err)
		}

		ret, err := MarshalOpenSSHPublicKey(pub)
		if err != nil {
			t.Error(err)
			continue
		}

		if ret != key {
			t.Fail()
		}
	}
}
