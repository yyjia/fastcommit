package fastcommit

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"testing"
)

var dataCase = rand4096data()

func rand4096data() []Account {
	ret := make([]Account, 4096)
	for i := uint64(0); i < 4096; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		ret[i] = Account{
			//key:   fr.NewElement(i),
			state: *new(fr.Element).SetBytes(seed),
		}
	}
	return ret
}
func TestValueCommit_Update(t *testing.T) {
	fc := NewContext(dataCase)
	seed := make([]byte, 32)
	rand.Read(seed)

	newData := Account{
		// key:   fr.NewElement(3),
		state: *new(fr.Element).SetBytes(seed),
	}

	err := fc.Update(3, newData.state)
	assert.Equal(t, nil, err)

	dataCase[3] = newData
	fc2 := NewContext(dataCase)
	if !fc.commit.Equal(&fc2.commit) {
		t.Fatalf("commit expect:  %v, get: %v", fc2.commit, fc.commit)
	}
}

//func TestValueCommit_Insert(t *testing.T) {
//	dataCase1 := dataCase[:4095]
//	fc := NewContext(dataCase1)
//
//	err := fc.Insert(dataCase[4095].key, dataCase[4095].state)
//	assert.Equal(t, nil, err)
//
//	fc2 := NewContext(dataCase)
//	if !fc.commit.Equal(&fc2.commit) {
//		t.Fatalf("commit expect:  %v, get: %v", fc2.commit, fc.commit)
//	}
//}

func TestValueCommit_BatchUpdate(t *testing.T) {
	fc := NewContext(dataCase)
	seed1 := make([]byte, 32)
	rand.Read(seed1)
	seed2 := make([]byte, 32)
	rand.Read(seed2)
	seed3 := make([]byte, 32)
	rand.Read(seed3)

	//keys := []fr.Element{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3)}
	values := []fr.Element{*new(fr.Element).SetBytes(seed1), *new(fr.Element).SetBytes(seed2), *new(fr.Element).SetBytes(seed3)}

	err := fc.BatchUpdate([]int{1, 2, 3}, values)
	assert.Equal(t, nil, err)

	dataCase[1] = Account{*new(fr.Element).SetBytes(seed1)}
	dataCase[2] = Account{*new(fr.Element).SetBytes(seed2)}
	dataCase[3] = Account{*new(fr.Element).SetBytes(seed3)}
	fc2 := NewContext(dataCase)
	if !fc.commit.Equal(&fc2.commit) {
		t.Fatalf("commit expect:  %v, get: %v", fc2.commit, fc.commit)
	}
}

func TestValueCommit_Proof_Verify(t *testing.T) {
	fc := NewContext(dataCase)
	proof, err := fc.Proof()
	assert.Equal(t, nil, err)

	err = fc.Verify(proof)
	assert.Equal(t, nil, err)
}

func TestValueCommit_ProofForKey_VerifyForKey(t *testing.T) {
	fc := NewContext(dataCase)

	// random a key
	p := fr.NewElement(9)
	proof, err := fc.ProofForVal(p)
	assert.Equal(t, nil, err)

	output, err := domains.EvaluateLagrangePolynomial(fc.values, p)
	assert.Equal(t, nil, err)

	err = fc.VerifyForVal(p, *output, proof)
	assert.Equal(t, nil, err)

	k2 := domains.Roots[4000]
	proof, err = fc.ProofForVal(k2)
	assert.Equal(t, nil, err)

	output, err = domains.EvaluateLagrangePolynomial(fc.values, k2)
	assert.Equal(t, nil, err)
	assert.Equal(t, fc.values[4000], *output)

	err = fc.VerifyForVal(k2, *output, proof)
	assert.Equal(t, nil, err)
}

func TestBranchs(t *testing.T) {
	for i := uint64(0); i < 100000; i++ {
		Updates(int(i), *new(fr.Element).SetUint64(i))
	}
}
