package paillier

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

const SECURITY_PARAMETER = 128

type RangeProofError struct{}

func (e RangeProofError) Error() string {
	return "Range proof error"
}

type RangeProofNi struct {
	Ek             PublicKey
	RangeVal       *big.Int
	Ciphertext     *big.Int
	EncryptedPairs EncryptedPairs
	Proof          Proof
	ErrorFactor    int
}

func Prove(ek PublicKey, rangeVal, ciphertext, secretX, secretR *big.Int) (RangeProofNi, error) {
	rp := RangeProof{}
	encryptedPairs, dataRandomnessPairs := rp.GenerateEncryptedPairs(ek, rangeVal, SECURITY_PARAMETER)
	c1, c2 := encryptedPairs.C1, encryptedPairs.C2

	vec := make([]*big.Int, 0)
	vec = append(vec, ek.N)
	vec = append(vec, c1...)
	vec = append(vec, c2...)
	e := NewChallengeBits(ComputeDigest(vec))

	// assuming digest length > error factor
	proof := rp.GenerateProof(ek, secretX, secretR, e, rangeVal, dataRandomnessPairs, SECURITY_PARAMETER)

	return RangeProofNi{
		Ek:             ek,
		RangeVal:       rangeVal,
		Ciphertext:     ciphertext,
		EncryptedPairs: encryptedPairs,
		Proof:          proof,
		ErrorFactor:    SECURITY_PARAMETER,
	}, nil
}

func (rpn *RangeProofNi) Verify(ek PublicKey, ciphertext *big.Int) error {
	if ek != rpn.Ek {
		return errors.New("EncryptionKey mismatch")
	}
	if ciphertext.Cmp(rpn.Ciphertext) != 0 {
		return errors.New("Ciphertext mismatch")
	}
	return rpn.VerifySelf()
}

func (rpn *RangeProofNi) VerifySelf() error {
	vec := make([]*big.Int, 0)
	vec = append(vec, rpn.Ek.N)
	vec = append(vec, rpn.EncryptedPairs.C1...)
	vec = append(vec, rpn.EncryptedPairs.C2...)
	e := NewChallengeBits(ComputeDigest(vec))

	rp := RangeProof{}
	err := rp.VerifierOutput(rpn.Ek, e, rpn.EncryptedPairs, rpn.Proof, rpn.RangeVal, rpn.Ciphertext, rpn.ErrorFactor)
	if err != nil {
		return RangeProofError{}
	}
	return nil
}

func ComputeDigest(values []*big.Int) []byte {
	h := sha256.New()
	for _, value := range values {
		h.Write(value.Bytes())
	}
	return h.Sum(nil)
}
