package fastcommit

import (
	"errors"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"math/big"
)

const POLY_SIZE = 4096

var (
	ErrFullSize = errors.New("array size is full")
	ErrMissKey  = errors.New("miss key")
)

type Account struct {
	key   fr.Element
	state fr.Element
}

type ValueCommit struct {
	commit bls12381.G1Affine
	keys   map[fr.Element]int
	values []fr.Element
	size   int
}

func NewContext(data []Account) *ValueCommit {
	keyInd := make(map[fr.Element]int, POLY_SIZE)
	vals := make([]fr.Element, POLY_SIZE)
	for i := 0; i < len(data); i++ {
		keyInd[data[i].key] = i
		vals[i] = data[i].state
	}
	c, err := kzg.Commit(vals, srs.Pk, 0)
	if nil != err {
		panic(err)
	}
	return &ValueCommit{
		keys:   keyInd,
		values: vals,
		size:   len(data),
		commit: c,
	}
}

func (s *ValueCommit) Update(k, v fr.Element) error {
	if _, ok := s.keys[k]; !ok {
		return ErrMissKey
	}
	index := s.keys[k]
	sub := new(fr.Element).Sub(&v, &s.values[index])
	bInt := new(big.Int)
	sub.BigInt(bInt)

	addC := new(bls12381.G1Affine).ScalarMultiplication(&srs.Pk.G1[index], bInt)
	s.commit = *new(bls12381.G1Affine).Add(&s.commit, addC)
	return nil
}

func (s *ValueCommit) Insert(k, v fr.Element) error {
	if s.size >= 4096 {
		return ErrFullSize
	}
	s.values[s.size] = v
	s.keys[k] = s.size

	bInt := new(big.Int)
	v.BigInt(bInt)
	addC := new(bls12381.G1Affine).ScalarMultiplication(&srs.Pk.G1[s.size], bInt)
	s.commit = *new(bls12381.G1Affine).Add(&s.commit, addC)
	s.size++
	return nil
}
