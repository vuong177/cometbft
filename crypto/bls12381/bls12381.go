package bls12381

import (
	cmtjson "github.com/cometbft/cometbft/libs/json"
)

const (
	PrivKeyName = "tendermint/PrivKeyBls12-381"
	PubKeyName  = "tendermint/PubKeyBls12-381"
)

func init() {
	cmtjson.RegisterType(PubKey{}, PubKeyName)
	cmtjson.RegisterType(PrivKey{}, PrivKeyName)

}
