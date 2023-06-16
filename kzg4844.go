package fastcommit

import (
	"bytes"
	"embed"
	"encoding/hex"
	"encoding/json"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/kzg"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"sync"
)

//go:embed trusted_setup.json
var content embed.FS

var srs kzg.SRS

func init() {
	gokzgInit()
}

// gokzgInit copyed from [https://github.com/crate-crypto/go-kzg-4844/blob/master/trusted_setup.go]
func gokzgInit() {
	config, err := content.ReadFile("trusted_setup.json")
	if err != nil {
		panic(err)
	}
	params := new(gokzg4844.JSONTrustedSetup)
	if err = json.Unmarshal(config, params); err != nil {
		panic(err)
	}
	//context, err = gokzg4844.NewContext4096(params)
	//if err != nil {
	//	panic(err)
	//}
	// Parse the trusted setup from hex strings to G1 and G2 points
	genG1, setupLagrangeG1Points, setupG2Points, err := parseTrustedSetup(params)
	if err != nil {
		panic(err)
	}

	// Get the generator points and the degree-1 element for G2 points
	// The generators are the degree-0 elements in the trusted setup
	//
	// This will never panic as we checked the minimum SRS size is >= 2
	// and `ScalarsPerBlob` is 4096
	//genG2 := setupG2Points[0]
	//alphaGenG2 := setupG2Points[1]
	srs.Vk = kzg.VerifyingKey{[2]bls12381.G2Affine{setupG2Points[0], setupG2Points[1]}, genG1}
	srs.Pk = kzg.ProvingKey{setupLagrangeG1Points}

	//domain := kzg.NewDomain(ScalarsPerBlob)
	//// Bit-Reverse the roots and the trusted setup according to the specs
	//// The bit reversal is not needed for simple KZG however it was
	//// implemented to make the step for full dank-sharding easier.
	//commitKey.ReversePoints()
	//domain.ReverseRoots()
}

// parseTrustedSetup parses the trusted setup in `JSONTrustedSetup` format
// which contains hex encoded strings to corresponding group elements.
// Elements are assumed to be well-formed.
func parseTrustedSetup(trustedSetup *gokzg4844.JSONTrustedSetup) (bls12381.G1Affine, []bls12381.G1Affine, []bls12381.G2Affine, error) {
	// Take the generator point from the monomial SRS
	if len(trustedSetup.SetupG1) < 1 {
		return bls12381.G1Affine{}, nil, nil, kzg.ErrMinSRSSize
	}
	genG1, err := parseG1PointNoSubgroupCheck(trustedSetup.SetupG1[0])
	if err != nil {
		return bls12381.G1Affine{}, nil, nil, err
	}

	setupLagrangeG1Points := parseG1PointsNoSubgroupCheck(trustedSetup.SetupG1Lagrange[:])
	g2Points := parseG2PointsNoSubgroupCheck(trustedSetup.SetupG2)
	return genG1, setupLagrangeG1Points, g2Points, nil
}

// parseG1PointNoSubgroupCheck parses a hex-string (with the 0x prefix) into a G1 point.
//
// This function performs no (expensive) subgroup checks, and should only be used
// for trusted inputs.
func parseG1PointNoSubgroupCheck(hexString string) (bls12381.G1Affine, error) {
	byts, err := hex.DecodeString(trim0xPrefix(hexString))
	if err != nil {
		return bls12381.G1Affine{}, err
	}

	var point bls12381.G1Affine
	noSubgroupCheck := bls12381.NoSubgroupChecks()
	d := bls12381.NewDecoder(bytes.NewReader(byts), noSubgroupCheck)

	return point, d.Decode(&point)
}

// parseG2PointsNoSubgroupCheck parses a slice hex-string (with the 0x prefix) into a
// slice of G2 points.
//
// This is essentially a parallelized version of calling [parseG2PointNoSubgroupCheck]
// on each element of the slice individually.
//
// This function performs no (expensive) subgroup checks, and should only be used
// for trusted inputs.
func parseG2PointsNoSubgroupCheck(hexStrings []string) []bls12381.G2Affine {
	numG2 := len(hexStrings)
	g2Points := make([]bls12381.G2Affine, numG2)

	var wg sync.WaitGroup
	wg.Add(numG2)
	for i := 0; i < numG2; i++ {
		go func(_i int) {
			g2Point, err := parseG2PointNoSubgroupCheck(hexStrings[_i])
			if err != nil {
				panic(err)
			}
			g2Points[_i] = g2Point
			wg.Done()
		}(i)
	}
	wg.Wait()

	return g2Points
}

// parseG2PointNoSubgroupCheck parses a hex-string (with the 0x prefix) into a G2 point.
//
// This function performs no (expensive) subgroup checks, and should only be used
// for trusted inputs.
func parseG2PointNoSubgroupCheck(hexString string) (bls12381.G2Affine, error) {
	byts, err := hex.DecodeString(trim0xPrefix(hexString))
	if err != nil {
		return bls12381.G2Affine{}, err
	}

	var point bls12381.G2Affine
	noSubgroupCheck := bls12381.NoSubgroupChecks()
	d := bls12381.NewDecoder(bytes.NewReader(byts), noSubgroupCheck)

	return point, d.Decode(&point)
}

// trim0xPrefix removes the "0x" from a hex-string.
func trim0xPrefix(hexString string) string {
	// Check that we are trimming off 0x
	if hexString[0:2] != "0x" {
		panic("hex string is not prefixed with 0x")
	}
	return hexString[2:]
}

// parseG1PointsNoSubgroupCheck parses a slice hex-string (with the 0x prefix) into a
// slice of G1 points.
//
// This is essentially a parallelized version of calling [parseG1PointNoSubgroupCheck]
// on each element of the slice individually.
//
// This function performs no (expensive) subgroup checks, and should only be used
// for trusted inputs.
func parseG1PointsNoSubgroupCheck(hexStrings []string) []bls12381.G1Affine {
	numG1 := len(hexStrings)
	g1Points := make([]bls12381.G1Affine, numG1)

	var wg sync.WaitGroup
	wg.Add(numG1)
	for i := 0; i < numG1; i++ {
		go func(j int) {
			g1Point, err := parseG1PointNoSubgroupCheck(hexStrings[j])
			if err != nil {
				panic(err)
			}
			g1Points[j] = g1Point
			wg.Done()
		}(i)
	}
	wg.Wait()

	return g1Points
}
