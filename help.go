package fastcommit

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	"github.com/panjf2000/ants/v2"
	"sync"
)

func allPoly(data []Account) {
	keys := make([]fr.Element, len(data))
	for i := range data {
		keys[i] = data[i].key
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(12, func(i interface{}) {
		defer wg.Done()
		poly := lagrange(keys, i.(int))
		kzg.Commit(poly, srs.Pk)
	})
	defer p.Release()

	for i := 0; i < len(keys); i++ {
		wg.Add(i)
		_ = p.Invoke(i)
	}
	wg.Wait()
}

func lagrange(keys []fr.Element, index int) []fr.Element {
	var one = fr.NewElement(1)
	var coefficients = []fr.Element{fr.NewElement(1)}
	var denominator fr.Element
	for i := 0; i < len(keys); i++ {
		if i == index {
			continue
		}
		coefficients = polynomialMul([]fr.Element{*new(fr.Element).Neg(&keys[i]), one}, coefficients)
		var tmp fr.Element
		tmp.Sub(&keys[index], &keys[i])
		denominator.Mul(&denominator, &tmp)
	}
	var denominatorInv fr.Element
	denominatorInv.Div(&one, &denominator)
	for i := range coefficients {
		coefficients[i].Mul(&coefficients[i], &denominatorInv)
	}

	return coefficients
}

func polynomialMul(a, b []fr.Element) []fr.Element {
	r := arrayOfZeroes(len(a) + len(b) - 1)

	var tmp fr.Element
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			tmp.Mul(&a[i], &b[j])
			r[i+j].Add(&r[i+j], &tmp)
		}
	}
	return r
}

func arrayOfZeroes(n int) []fr.Element {
	r := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		r[i] = fr.NewElement(0)
	}
	return r[:]
}
