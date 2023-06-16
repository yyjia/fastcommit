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
			key:   fr.NewElement(i),
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
		key:   fr.NewElement(3),
		state: *new(fr.Element).SetBytes(seed),
	}

	err := fc.Update(newData.key, newData.state)
	assert.Equal(t, nil, err)

	dataCase[3] = newData
	fc2 := NewContext(dataCase)
	if !fc.commit.Equal(&fc2.commit) {
		t.Fatalf("commit expect:  %v, get: %v", fc2.commit, fc.commit)
	}
}

func TestValueCommit_Insert(t *testing.T) {
	dataCase1 := dataCase[:4095]
	fc := NewContext(dataCase1)

	err := fc.Insert(dataCase[4095].key, dataCase[4095].state)
	assert.Equal(t, nil, err)

	fc2 := NewContext(dataCase)
	if !fc.commit.Equal(&fc2.commit) {
		t.Fatalf("commit expect:  %v, get: %v", fc2.commit, fc.commit)
	}
}
