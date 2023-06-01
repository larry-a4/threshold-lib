package bitvec

import (
	"math/bits"
)

type BitVec []uint32

func NewBitVecFromBytes(bytes []byte) BitVec {
	bitLen := len(bytes) * 8
	bitVec := make([]uint32, 0, (bitLen+31)/32)

	completeWords := len(bytes) / 4
	extraBytes := len(bytes) % 4

	for i := 0; i < completeWords; i++ {
		var accumulator uint32
		for j := 0; j < 4; j++ {
			accumulator |= uint32(ReverseBits(bytes[i*4+j])) << (j * 8)
		}
		bitVec = append(bitVec, accumulator)
	}

	if extraBytes > 0 {
		var lastWord uint32
		for i, b := range bytes[completeWords*4:] {
			lastWord |= uint32(ReverseBits(b)) << (i * 8)
		}
		bitVec = append(bitVec, lastWord)
	}

	return bitVec
}

func (b BitVec) GetBit(index int) bool {
	pos := index / 32
	j := uint(index % 32)
	return (b[pos] & (uint32(1) << j)) != 0
}

func (b BitVec) SetBit(index int, value bool) {
	pos := index / 32
	j := uint(index % 32)
	if value {
		b[pos] |= (uint32(1) << j)
	} else {
		b[pos] &= ^(uint32(1) << j)
	}
}

func (b BitVec) Len() int {
	return 32 * len(b)
}

// ReverseBits reverses the order of bits in a byte.
func ReverseBits(b byte) byte {
	return bits.Reverse8(b)
}
