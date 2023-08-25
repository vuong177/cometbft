package bls12381

import "crypto/subtle"

// IsZero checks if the secret key is a zero key.
func IsZero(sKey []byte) bool {
	b := byte(0)
	for _, s := range sKey {
		b |= s
	}
	return subtle.ConstantTimeByteEq(b, 0) == 1
}
