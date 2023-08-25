package bls12381

import (
	"github.com/cometbft/cometbft/crypto"
	"github.com/prysmaticlabs/prysm/v4/crypto/bls/blst"
	"github.com/prysmaticlabs/prysm/v4/crypto/bls/common"
)

type PrivKey struct {
	common.SecretKey
}

var _ crypto.PrivKey = PrivKey{}

// RandKey creates a new private key using a random method provided as an io.Reader.
func RandKey() (PrivKey, error) {
	secretKey, err := blst.RandKey()

	if err != nil {
		return PrivKey{}, err
	}
	return PrivKey{SecretKey: secretKey}, nil
}

func GenPrivKey() PrivKey {
	privKey, err := RandKey()
	if err != nil {
		panic(err)
	}
	return privKey
}

// Sign never return err
func (priv PrivKey) Sign(msg []byte) ([]byte, error) {
	return priv.SecretKey.Sign(msg).Marshal(), nil
}

func (priv PrivKey) Bytes() []byte {
	return priv.SecretKey.Marshal()
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherSr, ok := other.(PrivKey); ok {
		return privKey.PublicKey().Equals(otherSr.PublicKey())
	}
	return false
}

func (privKey PrivKey) PubKey() crypto.PubKey {
	return PubKey{
		privKey.PublicKey(),
	}
}

func (privKey PrivKey) Type() string {
	return PrivKeyName
}
