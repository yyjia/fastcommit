package fastcommit

import (
	"errors"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"math/big"

	//crateKzg "github.com/crate-crypto/go-kzg-4844/internal/kzg"
	crateKzg "github/yyjia/fastcommit/crateKzg/kzg"
)

const POLY_SIZE = 4096

var (
	ErrFullSize = errors.New("array size is full")
	ErrMissKey  = errors.New("miss key")
)

type Account struct {
	//key   fr.Element
	state fr.Element
}

type ValueCommit struct {
	commit bls12381.G1Affine
	//keys   map[fr.Element]int
	values []fr.Element
	//size   int
}

var branchs []ValueCommit

func Updates(indexs int, stat fr.Element) error {
	blob := indexs / POLY_SIZE
	idx := indexs % POLY_SIZE

	if blob >= len(branchs) {
		vals := make([]fr.Element, POLY_SIZE)
		c, err := kzg.Commit(vals, srs.Pk, 0)
		if nil != err {
			return err
		}

		branchs = append(branchs, ValueCommit{
			values: vals,
			commit: c,
		})
	}
	branchs[blob].Update(idx, stat)
	return nil
}

func NewContext(data []Account) *ValueCommit {
	//keyInd := make(map[fr.Element]int, POLY_SIZE)
	vals := make([]fr.Element, POLY_SIZE)
	for i := 0; i < len(data); i++ {
		//keyInd[data[i].key] = i
		vals[i] = data[i].state
	}
	c, err := kzg.Commit(vals, srs.Pk, 0)
	if nil != err {
		panic(err)
	}
	return &ValueCommit{
		//keys:   keyInd,
		values: vals,
		//size:   len(data),
		commit: c,
	}
}

func (s *ValueCommit) Update(index int, v fr.Element) error {
	//if _, ok := s.keys[k]; !ok {
	//	return ErrMissKey
	//}
	//index := s.keys[k]

	//sub := new(fr.Element).Sub(&v, &s.values[index])
	//bInt := new(big.Int)
	//sub.BigInt(bInt)

	bInt := new(fr.Element).Sub(&v, &s.values[index]).BigInt(new(big.Int))

	addC := new(bls12381.G1Affine).ScalarMultiplication(&srs.Pk.G1[index], bInt)
	s.commit = *new(bls12381.G1Affine).Add(&s.commit, addC)
	s.values[index] = v
	return nil
}

func (s *ValueCommit) BatchUpdate(indexs []int, vals []fr.Element) error {
	//if len(keys) != len(vals) {
	//	return fmt.Errorf("the length keys should equal vals")
	//}

	for i := 0; i < len(indexs); i++ {
		if err := s.Update(indexs[i], vals[i]); nil != err {
			return err
		}
	}
	return nil
}

//func (s *ValueCommit) Insert(k, v fr.Element) error {
//	if s.size >= 4096 {
//		return ErrFullSize
//	}
//	s.values[s.size] = v
//	s.keys[k] = s.size
//
//	bInt := new(big.Int)
//	v.BigInt(bInt)
//	addC := new(bls12381.G1Affine).ScalarMultiplication(&srs.Pk.G1[s.size], bInt)
//	s.commit = *new(bls12381.G1Affine).Add(&s.commit, addC)
//	s.size++
//	return nil
//}

func (s *ValueCommit) Proof() (bls12381.G1Affine, error) {
	evaluationChallenge := computeChallenge(s.values, s.commit)

	openingProof, err := crateKzg.Open(domains, s.values, evaluationChallenge, &crateKzg.CommitKey{G1: srs.Pk.G1}, 0)
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	return openingProof.QuotientCommitment, nil
}

func (s *ValueCommit) ProofForVal(evaluation fr.Element) (bls12381.G1Affine, error) {
	openingProof, err := crateKzg.Open(domains, s.values, evaluation, &crateKzg.CommitKey{G1: srs.Pk.G1}, 0)
	if nil != err {
		return bls12381.G1Affine{}, err
	}

	return openingProof.QuotientCommitment, nil
}

func (s *ValueCommit) ProofForVals(keys []fr.Element) (bls12381.G1Affine, error) {

	return bls12381.G1Affine{}, nil
}

func (s *ValueCommit) Verify(proof bls12381.G1Affine) error {
	evaluationChallenge := computeChallenge(s.values, s.commit)
	outputPoint, err := domains.EvaluateLagrangePolynomial(s.values, evaluationChallenge)
	if nil != err {
		return err
	}
	return crateKzg.Verify(&s.commit, &crateKzg.OpeningProof{proof, evaluationChallenge, *outputPoint}, &crateKzg.OpeningKey{
		srs.Vk.G1,
		srs.Vk.G2[0],
		srs.Vk.G2[1],
	})
}

func (s *ValueCommit) VerifyForVal(evaluation, output fr.Element, proof bls12381.G1Affine) error {
	return crateKzg.Verify(&s.commit, &crateKzg.OpeningProof{proof, evaluation, output}, &crateKzg.OpeningKey{
		srs.Vk.G1,
		srs.Vk.G2[0],
		srs.Vk.G2[1],
	})
}
