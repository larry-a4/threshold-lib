package paillier

import (
	"errors"
	"math/big"
	"math/rand"

	"github.com/okx/threshold-lib/crypto"
	"github.com/okx/threshold-lib/crypto/bitvec"
)

// type ChallengeBits struct {
// 	Bits []byte `json:"bits"`
// }

// func NewChallengeBits(bits []byte) ChallengeBits {
// 	return ChallengeBits{Bits: bits}
// }

type ChallengeBits []byte

func NewChallengeBits(bits []byte) ChallengeBits {
	return bits
}

type DataRandomnessPairs struct {
	W1 []*big.Int
	W2 []*big.Int
	R1 []*big.Int
	R2 []*big.Int
}

type EncryptedPairs struct {
	C1 []*big.Int `json:"c1"`
	C2 []*big.Int `json:"c2"`
}

type Response struct {
	Open *Open
	Mask *Mask
}

type Open struct {
	W1 *big.Int `json:"w1"`
	R1 *big.Int `json:"r1"`
	W2 *big.Int `json:"w2"`
	R2 *big.Int `json:"r2"`
}

type Mask struct {
	J       uint8    `json:"j"`
	MaskedX *big.Int `json:"masked_x"`
	MaskedR *big.Int `json:"masked_r"`
}

type Proof struct {
	Responses []Response `json:"responses"`
}

type Randomness *big.Int
type RawPlaintext *big.Int

type RangeProofTrait interface {
	GenerateEncryptedPairs(ek PublicKey, rangeVal *big.Int, errorFactor int) (EncryptedPairs, DataRandomnessPairs)
	GenerateProof(ek PublicKey, secretX, secretR *big.Int, e ChallengeBits, rangeVal *big.Int, data DataRandomnessPairs, errorFactor int) Proof
	VerifierOutput(ek PublicKey, e ChallengeBits, encryptedPairs EncryptedPairs, proof Proof, rangeVal, cipherX *big.Int, errorFactor int) error
}

type RangeProof struct{}

func (rp RangeProof) GenerateEncryptedPairs(ek PublicKey, rangeVal *big.Int, errorFactor int) (EncryptedPairs, DataRandomnessPairs) {
	two := big.NewInt(2)
	three := big.NewInt(3)

	rangeScaledThird := new(big.Int).Div(rangeVal, three)
	rangeScaledTwoThirds := new(big.Int).Mul(two, rangeScaledThird)
	difference := new(big.Int).Sub(rangeScaledTwoThirds, rangeScaledThird)

	w1 := make([]*big.Int, errorFactor)
	w2 := make([]*big.Int, errorFactor)
	for i := 0; i < errorFactor; i++ {
		w2[i] = crypto.RandomNum(difference)
		w1[i] = new(big.Int).Add(rangeScaledThird, w2[i])
		if rand.Intn(2) == 0 {
			w1[i], w2[i] = w2[i], w1[i]
		}
	}

	r1 := make([]*big.Int, errorFactor)
	r2 := make([]*big.Int, errorFactor)
	for i := 0; i < errorFactor; i++ {
		r1[i] = crypto.RandomNum(ek.N)
		r2[i] = crypto.RandomNum(ek.N)
	}

	c1 := make([]*big.Int, errorFactor)
	c2 := make([]*big.Int, errorFactor)
	for i := 0; i < errorFactor; i++ {
		c1[i] = EncryptWithChosenRandomness(ek, w1[i], r1[i])
		c2[i] = EncryptWithChosenRandomness(ek, w2[i], r2[i])
	}

	return EncryptedPairs{C1: c1, C2: c2}, DataRandomnessPairs{W1: w1, W2: w2, R1: r1, R2: r2}
}

func (rp RangeProof) GenerateProof(ek PublicKey, secretX, secretR *big.Int, e ChallengeBits, rangeVal *big.Int, data DataRandomnessPairs, errorFactor int) Proof {
	two := big.NewInt(2)
	three := big.NewInt(3)

	rangeScaledThird := new(big.Int).Div(rangeVal, three)
	rangeScaledTwoThirds := new(big.Int).Mul(two, rangeScaledThird)

	bitsOfE := bitvec.NewBitVecFromBytes(e)

	responses := make([]Response, errorFactor)
	for i := 0; i < errorFactor; i++ {
		ei := bitsOfE.GetBit(i)
		if !ei {
			responses[i] = Response{
				Open: &Open{
					W1: data.W1[i],
					R1: data.R1[i],
					W2: data.W2[i],
					R2: data.R2[i],
				},
			}
		} else {
			secretXPlusW1 := new(big.Int).Add(secretX, data.W1[i])
			secretXPlusW2 := new(big.Int).Add(secretX, data.W2[i])
			if secretXPlusW1.Cmp(rangeScaledThird) == 1 && secretXPlusW1.Cmp(rangeScaledTwoThirds) == -1 {
				responses[i] = Response{
					Mask: &Mask{
						J:       1,
						MaskedX: secretXPlusW1,
						MaskedR: new(big.Int).Mod(new(big.Int).Mul(secretR, data.R1[i]), ek.N),
					},
				}
			} else {
				responses[i] = Response{
					Mask: &Mask{
						J:       2,
						MaskedX: secretXPlusW2,
						MaskedR: new(big.Int).Mod(new(big.Int).Mul(secretR, data.R2[i]), ek.N),
					},
				}
			}
		}
	}

	return Proof{Responses: responses}
}

func (rp RangeProof) VerifierOutput(ek PublicKey, e ChallengeBits, encryptedPairs EncryptedPairs, proof Proof, rangeVal, cipherX *big.Int, errorFactor int) error {
	three := big.NewInt(3)
	two := big.NewInt(2)

	rangeScaledThird := new(big.Int).Div(rangeVal, three)
	rangeScaledTwoThirds := new(big.Int).Mul(two, rangeScaledThird)

	bitsOfE := bitvec.NewBitVecFromBytes(e)

	verifications := make([]bool, errorFactor)
	for i := 0; i < errorFactor; i++ {
		ei := bitsOfE.GetBit(i) // Assuming Get(i) method returns the ith bit
		response := proof.Responses[i]
		if !ei {
			if response.Open == nil {
				verifications[i] = false
				continue
			}
			expectedC1i := EncryptWithChosenRandomness(ek, response.Open.W1, response.Open.R1)
			expectedC2i := EncryptWithChosenRandomness(ek, response.Open.W2, response.Open.R2)
			res := expectedC1i.Cmp(encryptedPairs.C1[i]) == 0 && expectedC2i.Cmp(encryptedPairs.C2[i]) == 0
			flag := response.Open.W1.Cmp(rangeScaledThird) == -1 && response.Open.W2.Cmp(rangeScaledThird) == 1 && response.Open.W2.Cmp(rangeScaledTwoThirds) == -1
			flag = flag || (response.Open.W2.Cmp(rangeScaledThird) == -1 && response.Open.W1.Cmp(rangeScaledThird) == 1 && response.Open.W1.Cmp(rangeScaledTwoThirds) == -1)
			verifications[i] = res && flag
		} else {
			if response.Mask == nil {
				verifications[i] = false
				continue
			}
			c := new(big.Int)
			if response.Mask.J == 1 {
				c.Mod(new(big.Int).Mul(encryptedPairs.C1[i], cipherX), ek.n2())
			} else {
				c.Mod(new(big.Int).Mul(encryptedPairs.C2[i], cipherX), ek.n2())
			}
			encZi := EncryptWithChosenRandomness(ek, response.Mask.MaskedX, response.Mask.MaskedR)
			res := c.Cmp(encZi) == 0
			verifications[i] = res && response.Mask.MaskedX.Cmp(rangeScaledThird) == 1 && response.Mask.MaskedX.Cmp(rangeScaledTwoThirds) == -1
		}
	}

	for _, v := range verifications {
		if !v {
			return errors.New("CorrectKeyProofError")
		}
	}

	return nil
}

func EncryptWithChosenRandomness(ek PublicKey, m RawPlaintext, r Randomness) *big.Int {
	var rn, gm, c, ekN, temp *big.Int

	one := big.NewInt(1)
	nn := ek.n2()

	// Compute rn = r^ek.n mod ek.nn
	rn.Exp(r, ek.N, nn)

	// Compute gm = (m * ek.n + 1) mod ek.nn
	ekN.Mul(m, ek.N)
	temp.Add(ekN, one)
	gm.Mod(temp, nn)

	// Compute c = (gm * rn) mod ek.nn
	temp.Mul(gm, rn)
	c.Mod(temp, nn)

	return c
}
