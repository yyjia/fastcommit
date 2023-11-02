package fastcommit

import (
	"bytes"
	"crypto/sha256"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	crateKzg "github.com/kzgstate/crateKzg/kzg"
	"math/big"
)

type Material struct {
	k uint32
	v fr.Element
}

type params struct {
	k fr.Element
	v fr.Element
	c bls12381.G1Affine
	r big.Int
}

type NeedParams struct {
	ps []params
	r  big.Int
}

func (s *Material) parseParams() NeedParams {
	res := make([]params, 3)
	gb := make([][]byte, 0, 9)

	// level 1
	b := s.k / POLY_SIZE
	i := s.k % POLY_SIZE
	cp1 := Branchs[b].C()
	bt := cp1.Bytes()
	w := domains.Roots[i]
	wb := w.Bytes()
	vb := s.v.Bytes()

	exist := Branchs[b].values[i].Bytes()
	if !bytes.Equal(vb[:], exist[:]) {
		panic("不存在的 k, v")
	}
	r := hash256(wb[:], vb[:], bt[:])
	res[0] = params{w, s.v, *cp1, *new(big.Int).SetBytes(r[:])}
	gb = append(gb, wb[:], vb[:], bt[:])

	// level 2
	i = b % POLY_SIZE
	b = b / POLY_SIZE
	cp2 := Branchs1[b].C()
	bt = cp2.Bytes()
	w = domains.Roots[i]
	wb = w.Bytes()
	v := Branchs1[b].values[i]
	vb = v.Bytes()
	r = hash256(wb[:], vb[:], bt[:])
	res[1] = params{w, v, *cp2, *new(big.Int).SetBytes(r[:])}
	gb = append(gb, wb[:], vb[:], bt[:])

	i = b % POLY_SIZE
	b = b / POLY_SIZE
	cp3 := Branchs2[b].C()
	bt = cp3.Bytes()
	w = domains.Roots[i]
	wb = w.Bytes()
	v = Branchs2[b].values[i]
	vb = v.Bytes()
	r = hash256(wb[:], vb[:], bt[:])
	res[2] = params{w, v, *cp3, *new(big.Int).SetBytes(r[:])}
	gb = append(gb, wb[:], vb[:], bt[:])

	r0 := hash256(gb...)
	return NeedParams{
		res, *new(big.Int).SetBytes(r0[:]),
	}
}

func hash256(ins ...[]byte) [32]byte {
	buf := bytes.Buffer{}
	buf.Reset()
	for _, v := range ins {
		buf.Write(v)
	}
	return sha256.Sum256(buf.Bytes())
}

// CompressCommit Return D
// D 是对 g(x) 的 commit
func (s *Material) CompressCommit(needP NeedParams) bls12381.G1Affine {
	// r_i = hash(x_i,y_i,C_i)
	// g(x) = r_0* (f_0(x)-y_i)/(x-x_i) + ...+ r_i* (f_i(x)-y_i)/(x-x_i)
	// g(s) = r_0*q_0(s) + ... + r_i(q_i(s))

	// 假设我们固定有3层
	var gC bls12381.G1Affine
	//needP := s.parseParams()

	// 第一层
	blob := s.k / POLY_SIZE
	vc := Branchs[blob]
	//q_i(x)
	P, err := vc.ProofForVal(needP.ps[0].k)
	if nil != err {
		panic(err)
	}

	P.ScalarMultiplication(&P, &needP.ps[0].r)
	gC.Add(&gC, &P)

	// 第二层
	blob = blob / POLY_SIZE
	vc = Branchs1[blob]
	P, err = vc.ProofForVal(needP.ps[1].k)
	if nil != err {
		panic(err)
	}
	P.ScalarMultiplication(&P, &needP.ps[1].r)
	gC.Add(&gC, &P)

	// 第三层
	blob = blob / POLY_SIZE
	vc = Branchs2[blob]
	P, err = vc.ProofForVal(needP.ps[2].k)
	if nil != err {
		panic(err)
	}
	P.ScalarMultiplication(&P, &needP.ps[2].r)
	gC.Add(&gC, &P)
	return gC
}

// challengePoint compute t
// hash(D,r)
func (s *Material) challengePoint(commit [48]byte, r [32]byte) fr.Element {
	h := hash256(commit[:], r[:])
	return *new(fr.Element).SetBytes(h[:])
}

// G1 compute g1(x) commit = E
func (s *Material) G1(np NeedParams, t fr.Element) bls12381.G1Affine {
	c := new(bls12381.G1Affine)
	for _, p := range np.ps {
		tt := new(fr.Element)
		tt.Sub(&t, &p.k)
		tt.Inverse(tt)
		tt.Mul(tt, new(fr.Element).SetBigInt(&p.r))
		tmp := new(bls12381.G1Affine).ScalarMultiplication(&p.c, tt.BigInt(new(big.Int)))
		c.Add(c, tmp)
	}
	return *c
}

// G2point 计算 g2(t) = y
func (s *Material) G2point(np NeedParams, t fr.Element) fr.Element {
	res := new(fr.Element)
	for _, p := range np.ps {
		tt := new(fr.Element)
		tt.Sub(&t, &p.k)
		tt.Inverse(tt)
		tt.Mul(tt, new(fr.Element).SetBigInt(&p.r))
		tt.Mul(tt, &p.v)
		res.Add(res, tt)
	}
	return *res
}

// proof g2(x) 的承诺
func (s *Material) proof(np NeedParams, t fr.Element, y fr.Element) (bls12381.G1Affine, error) {
	// [(E-D-y)/(s-t)]_1
	//np := s.parseParams()
	//D := s.CompressCommit(np)
	//var rt [32]byte
	//copy(rt[:], np.r.Bytes())
	//t := s.challengePoint(D.Bytes(), rt)
	//y := s.G2point(np, *new(fr.Element).SetBigInt(&np.r))

	//E := s.G1(np, t)
	//
	//res := new(bls12381.G1Affine).Sub(&E, &D)
	//yG1 := new(bls12381.G1Affine).ScalarMultiplication(&srs.Pk.G1[0], y.BigInt(new(big.Int)))
	//res.Sub(res, yG1)
	//
	//tG1 := new(bls12381.G1Affine).ScalarMultiplication(&srs.Vk.G1, t.BigInt(new(big.Int)))
	//// [s-t]_1
	//g1 := new(bls12381.G1Affine).Sub(&srs.Pk.G1[1], tG1)

	// 第一层
	b := s.k / POLY_SIZE
	vc0 := Branchs[b]
	// 第二层
	b = b / POLY_SIZE
	vc1 := Branchs1[b]
	// 第三层
	b = b / POLY_SIZE
	vc2 := Branchs2[b]

	// 第一层
	xyz0 := np.ps[0]
	//f1(x)-y_1 / (x-z_1)
	qPoly0, err := domains.ComputeQuotientPoly(vc0.values, xyz0.k, xyz0.v)
	if nil != err {
		return bls12381.G1Affine{}, err
	}

	// 第二层
	xyz1 := np.ps[1]
	qPoly1, err := domains.ComputeQuotientPoly(vc1.values, xyz1.k, xyz1.v)
	if nil != err {
		return bls12381.G1Affine{}, err
	}

	// 第三层
	xyz2 := np.ps[2]
	qPoly2, err := domains.ComputeQuotientPoly(vc2.values, xyz2.k, xyz2.v)
	if nil != err {
		return bls12381.G1Affine{}, err
	}

	qpoly := make([]fr.Element, POLY_SIZE)
	for i, x := range domains.Roots {
		// 第一层
		// t-z_1
		r1 := new(fr.Element).Sub(&t, &xyz0.k)
		// 1/(t-z_1)
		r1.Inverse(r1)
		// f1(x)/(t-z_1)
		r1.Mul(r1, &vc0.values[i])
		r1.Sub(r1, &qPoly0[i])
		r1.Mul(r1, new(fr.Element).SetBigInt(&xyz0.r))

		// 第二层
		r2 := new(fr.Element).Sub(&t, &xyz1.k)
		// 1/(t-z_1)
		r2.Inverse(r2)
		// f1(x)/(t-z_1)
		r2.Mul(r2, &vc1.values[i])
		r2.Sub(r2, &qPoly1[i])
		r2.Mul(r2, new(fr.Element).SetBigInt(&xyz1.r))

		// 第三层
		r3 := new(fr.Element).Sub(&t, &xyz2.k)
		// 1/(t-z_1)
		r3.Inverse(r3)
		// f1(x)/(t-z_1)
		r3.Mul(r3, &vc2.values[i])
		r3.Sub(r3, &qPoly2[i])
		r3.Mul(r3, new(fr.Element).SetBigInt(&xyz2.r))

		// -Y
		r1.Add(r1, r2)
		r1.Add(r1, r3)
		r1.Sub(r1, &y)
		// 1/(x-t)
		qt := new(fr.Element).Sub(&x, &t)
		qt.Inverse(qt)
		r1.Mul(r1, qt)
		qpoly[i] = *r1
	}

	c, err := crateKzg.Commit(qpoly, &crateKzg.CommitKey{G1: srs.Pk.G1}, 0)
	return *c, err
}

func (s *Material) Verify(np NeedParams, D bls12381.G1Affine, proof bls12381.G1Affine) error {
	var rt [32]byte
	copy(rt[:], np.r.Bytes())
	t := s.challengePoint(D.Bytes(), rt)

	y := s.G2point(np, t)

	E := s.G1(np, t)
	// E-D
	E.Sub(&E, &D)

	return crateKzg.Verify(&E, &crateKzg.OpeningProof{
		QuotientCommitment: proof,
		InputPoint:         t,
		ClaimedValue:       y,
	}, &crateKzg.OpeningKey{
		srs.Vk.G1, srs.Vk.G2[0], srs.Vk.G2[1],
	})
}
