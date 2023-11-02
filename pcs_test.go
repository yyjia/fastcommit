package fastcommit

import (
	"context"
	"fmt"
	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon-lib/kv"
	mdbx2 "github.com/ledgerwatch/erigon-lib/kv/mdbx"
	"github.com/stretchr/testify/assert"
	"github.com/torquem-ch/mdbx-go/mdbx"
	"golang.org/x/sync/semaphore"
	"log"
	"sync/atomic"
	"testing"
)

var accounts = make(map[common.Address]uint32, 215785283)

func prepareTestData(t *testing.T) {
	from := "/Users/mac/Downloads"
	logger := log.New()
	//src := mdbx2.NewMDBX(logger).Path(from).Flags(func(flags uint) uint { return mdbx.Readonly | mdbx.Accede }).MustOpen()
	const ThreadsHardLimit = 9_000
	src := mdbx2.NewMDBX(logger).Path(from).
		Label(0).
		RoTxsLimiter(semaphore.NewWeighted(ThreadsHardLimit)).
		WithTableCfg(func(_ kv.TableCfg) kv.TableCfg { return kv.TablesCfgByLabel(0) }).
		Flags(func(flags uint) uint { return flags | mdbx.Readonly | mdbx.Accede }).
		MustOpen()

	ctx := context.Background()
	srcTx, err1 := src.BeginRo(ctx)
	if err1 != nil {
		t.Fatal(err1)
	}
	defer srcTx.Rollback()

	name := "AccountChangeSet"
	clean := kv.ReadAhead(ctx, src, &atomic.Bool{}, name, nil, 1<<31-1)
	clean()

	srcC, err := srcTx.CursorDupSort(name)
	if err != nil {
		t.Fatal(err)
	}
	defer srcTx.Rollback()

	//logged := time.Now()
	var tol, j uint64
	var idx uint32
	var ok bool
	all, _ := srcC.Count()
	fmt.Printf("Make KZG form %s %s bucket %d\r\n", from, name, all)
	k, v, err := srcC.First()
	if err != nil {
		t.Fatal(err)
	}
	j = 0
	for ; err == nil && k != nil; k, v, err = srcC.NextDup() {
		tol++
		//	key - blockNum_u64
		//	value - address + account(encoded)
		//blockN = binary.BigEndian.Uint64(k)
		var address common.Address
		copy(address[0:20], v[0:20])
		if idx, ok = accounts[address]; !ok {
			idx = uint32(len(accounts))
			accounts[address] = idx
		}
		//fmt.Println("address", address, HashToBLSField(v[20:]))
		Updates(int(idx), HashToBLSField(v[20:]))
		j++
	}
	Wg.Wait()
	PrintArrCommit(Branchs)
	UpdatesRoot()
}

func Test_MergeProof(t *testing.T) {
	prepareTestData(t)

	// 我们承诺 0xD18eb9e1D285dAbE93e5D4bAE76BEEFe43b521e8 这个地址处的 state
	addr := common.HexToAddress("0xD18eb9e1D285dAbE93e5D4bAE76BEEFe43b521e8")
	k := accounts[addr]

	blob := k / POLY_SIZE
	ind := k % POLY_SIZE

	v := Branchs[blob].values[ind]

	instance := &Material{k: k, v: v}

	// 路径上的参数
	np := instance.parseParams()
	l1 := np.ps[0]
	b1 := l1.c.Bytes()

	l2 := np.ps[1]
	assert.Equal(t, l2.v, HashToBLSField(b1[:]))

	b2 := l2.c.Bytes()
	l3 := np.ps[2]
	assert.Equal(t, l3.v, HashToBLSField(b2[:]))

	// g(x) 承诺
	D := instance.CompressCommit(np)

	var rt [32]byte
	copy(rt[:], np.r.Bytes())
	// 挑战点
	input := instance.challengePoint(D.Bytes(), rt)

	// 值
	output := instance.G2point(np, input)

	// 计算 proof
	proof, err := instance.proof(np, input, output)
	assert.Equal(t, nil, err)

	// 验证
	err = instance.Verify(np, D, proof)
	assert.Equal(t, nil, err)
}
