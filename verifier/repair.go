package verifier

// Reads signatures written by an encoder that gets one thing wrong.
//
// An EdDSA signature is two 32-octet values, R and S, each stored as an OpenPGP
// MPI: a two-octet bit count, then the value with its leading zero octets
// removed. The iOS core up to CarrierPony 3.2.x computed the bit count
// correctly but then wrote all 32 octets, leading zeros included. When R or S
// begins with a zero octet (about one signature in 128) the count says 31
// octets and 32 follow, so a reader that trusts the count takes the wrong
// octets and the signature does not verify.
//
// Every key carries self-signatures, so about one iOS-made identity in a
// hundred has a public key this library would refuse outright. GnuPG reads
// those keys, and the people who hold them log in today.
//
// The value is all there, only mislabelled, and the signature's hash does not
// cover how R and S are encoded. So such a packet can be rewritten in the
// correct form without changing what it means: if the two MPIs do not fill the
// signature area by their own counts, and the area is exactly the 68 octets
// that two full-width values take, and each count is what the full 32-octet
// value would give, then it is this encoder and R and S are the two 32-octet
// halves. Anything else is left exactly as it was.
//
// This only ever makes a mislabelled signature readable. Whether it then
// verifies is still decided by the cryptography, so nothing here can make a
// forged signature pass. The same rule as CPSignatureRepair in the Android core.

import "math/bits"

const (
	tagSignature = 2
	eddsaLegacy  = 22
	valueLength  = 32
	fullArea     = 2 * (2 + valueLength)
)

// normalize returns data (a binary key or any sequence of definite-length
// packets) with every mislabelled v4 EdDSA signature rewritten correctly. It
// returns data itself when there is nothing to repair or the bytes are not a
// clean packet sequence.
func normalize(data []byte) []byte {
	out := make([]byte, 0, len(data))
	changed := false
	i := 0
	for i < len(data) {
		tag, bodyStart, bodyLength, ok := header(data, i)
		if !ok {
			return data
		}
		end := bodyStart + bodyLength
		if bodyLength < 0 || end > len(data) || end <= i {
			return data
		}
		var repaired []byte
		if tag == tagSignature {
			repaired = repairBody(data[bodyStart:end])
		}
		if repaired != nil {
			out = append(out, packetBytes(tagSignature, repaired)...)
			changed = true
		} else {
			out = append(out, data[i:end]...)
		}
		i = end
	}
	if !changed {
		return data
	}
	return out
}

// repairBody returns the corrected body of a mislabelled v4 EdDSA signature
// packet, or nil if body is not one.
func repairBody(body []byte) []byte {
	if len(body) < 10 || body[0] != 4 || body[2] != eddsaLegacy {
		return nil
	}
	i := 4
	i += 2 + uint16At(body, i)
	if i+2 > len(body) {
		return nil
	}
	i += 2 + uint16At(body, i)
	i += 2
	if i > len(body) {
		return nil
	}
	area := body[i:]
	if fillsExactly(area) || len(area) != fullArea {
		return nil
	}
	r := area[2 : 2+valueLength]
	s := area[4+valueLength : fullArea]
	if uint16At(area, 0) != bitLength(r) || uint16At(area, 2+valueLength) != bitLength(s) {
		return nil
	}
	out := append([]byte{}, body[:i]...)
	out = append(out, mpi(r)...)
	return append(out, mpi(s)...)
}

// fillsExactly reports whether two MPIs, read by their own bit counts, use up
// area exactly.
func fillsExactly(area []byte) bool {
	off := 0
	for n := 0; n < 2; n++ {
		if off+2 > len(area) {
			return false
		}
		off += 2 + (uint16At(area, off)+7)/8
		if off > len(area) {
			return false
		}
	}
	return off == len(area)
}

func bitLength(value []byte) int {
	for index, b := range value {
		if b != 0 {
			return (len(value)-index-1)*8 + bits.Len8(b)
		}
	}
	return 0
}

func mpi(value []byte) []byte {
	first := 0
	for first < len(value) && value[first] == 0 {
		first++
	}
	trimmed := value[first:]
	n := bitLength(trimmed)
	return append([]byte{byte(n >> 8), byte(n)}, trimmed...)
}

func uint16At(b []byte, offset int) int {
	return int(b[offset])<<8 | int(b[offset+1])
}

func packetBytes(tag int, body []byte) []byte {
	n := len(body)
	var head []byte
	switch {
	case n < 192:
		head = []byte{byte(0xC0 | tag), byte(n)}
	case n < 8384:
		head = []byte{byte(0xC0 | tag), byte((n-192)>>8 + 192), byte((n - 192) & 0xFF)}
	default:
		head = []byte{byte(0xC0 | tag), 0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(head, body...)
}

// header reads a definite-length packet header at start, old or new format.
func header(data []byte, start int) (tag, bodyStart, bodyLength int, ok bool) {
	i := start
	octet := func() (int, bool) {
		if i >= len(data) {
			return 0, false
		}
		i++
		return int(data[i-1]), true
	}
	uint32 := func() (int, bool) {
		if len(data)-i < 4 {
			return 0, false
		}
		v := int(data[i])<<24 | int(data[i+1])<<16 | int(data[i+2])<<8 | int(data[i+3])
		i += 4
		return v, true
	}
	c, good := octet()
	if !good || c&0x80 == 0 {
		return
	}
	var length int
	if c&0x40 != 0 {
		tag = c & 0x3F
		l0, good := octet()
		if !good {
			return
		}
		switch {
		case l0 < 192:
			length = l0
		case l0 < 224:
			l1, good := octet()
			if !good {
				return
			}
			length = (l0-192)<<8 + l1 + 192
		case l0 == 255:
			if length, good = uint32(); !good {
				return
			}
		default:
			return
		}
	} else {
		tag = (c >> 2) & 0x0F
		switch c & 0x03 {
		case 0:
			if length, good = octet(); !good {
				return
			}
		case 1:
			hi, good1 := octet()
			lo, good2 := octet()
			if !good1 || !good2 {
				return
			}
			length = hi<<8 | lo
		case 2:
			if length, good = uint32(); !good {
				return
			}
		default:
			return
		}
	}
	return tag, i, length, true
}
