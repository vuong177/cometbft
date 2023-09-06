package bls12381

import (
	"bytes"
	"fmt"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/prysmaticlabs/prysm/v4/config/params"
	"github.com/prysmaticlabs/prysm/v4/crypto/bls/blst"
)

// PubKey implements crypto.PubKey for the bls12-381 signature scheme.
type PubKey []byte

var _ crypto.PubKey = PubKey{}

var (
	KeyType = "bls12381"

	// PubKeySize is the number of bytes in an bls12-381 public key.
	PubKeySize = params.BeaconConfig().BLSPubkeyLength
)

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKey) Address() crypto.Address {

	return crypto.Address(tmhash.SumTruncated(pubKey.Bytes()[:]))
}

// Bytes returns the byte representation of the PubKey.
func (pubKey PubKey) Bytes() []byte {
	return pubKey
}

// Bytes returns the byte representation of the PubKey.
func FromBytes(bz []byte) PubKey {
	return bz
}

// Equals - checks that two public keys are the same time
// Runs in constant time based on length of the keys.
func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if otherSr, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey.Bytes()[:], otherSr.Bytes()[:])
	}

	return false
}

func (pubKey PubKey) VerifySignature(msg []byte, sigBytes []byte) bool {
	signature, err := blst.SignatureFromBytes(sigBytes)
	if err != nil {
		return false
	}
	blstPubKey, err := blst.PublicKeyFromBytes(pubKey)
	if err != nil {
		return false
	}

	if err != nil {
		return false
	}

	return signature.Verify(blstPubKey, msg)
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyBLS12-381{%s}", []byte(pubKey))
}

func (pubKey PubKey) Type() string {
	return KeyType
}
