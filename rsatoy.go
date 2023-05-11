package myrsatoy

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

type PublicKey struct {
	E *big.Int
	N *big.Int
}

type PrivateKey struct {
	D *big.Int
	N *big.Int
}

func GenerateKeys(bitLen int) (*PublicKey, *PrivateKey, error) {
	for i := 0; i < 10; i++ {

		p, err := rand.Prime(rand.Reader, bitLen/2)
		if err != nil {
			return nil, nil, err
		}

		q, err := rand.Prime(rand.Reader, bitLen/2)
		if err != nil {
			return nil, nil, err
		}

		n := new(big.Int).Set(p)
		n.Mul(n, q)

		if n.BitLen() != bitLen {
			continue
		}

		e := big.NewInt(65537)

		p.Sub(p, big.NewInt(1))
		q.Sub(q, big.NewInt(1))

		totient := p.Mul(p, q)

		d := new(big.Int).ModInverse(e, totient)
		if d == nil {
			continue
		}

		return &PublicKey{E: e, N: n}, &PrivateKey{D: d, N: n}, nil
	}
	return nil, nil, errors.New("retrying too many times, something is wrong")
}

func encrypt(pub *PublicKey, m *big.Int) *big.Int {
	c := new(big.Int)
	return c.Exp(m, pub.E, pub.N)
}

// decrypt performs decryption of the cipher c using a private key, and returns
// the decrypted message.
func decrypt(priv *PrivateKey, c *big.Int) *big.Int {
	m := new(big.Int)
	m.Exp(c, priv.D, priv.N)
	return m
}

func EncryptRSA(pub *PublicKey, m []byte) ([]byte, error) {
	keyLen := (pub.N.BitLen() + 7) / 8
	if len(m) > keyLen-11 {
		return nil, fmt.Errorf("len(m)=%v, too long", len(m))
	}

	// Pad bytes for the message according to RFC 2313
	// EB = 00 || 02 || PS || 00 || D
	dataForEncrypt := make([]byte, keyLen)
	dataForEncrypt[0] = 0x00
	dataForEncrypt[1] = 0x02

	psLen := keyLen - len(m) - 3

	for i := 0; i < psLen; {
		_, err := rand.Read(dataForEncrypt[i+2 : i+3])
		if err != nil {
			return nil, err
		}
		if dataForEncrypt[i+2] != 0x00 {
			i++
		}
	}

	dataForEncrypt[2+psLen] = 0x00

	copy(dataForEncrypt[3+psLen:], m)

	// Encrypt the padded message
	mnum := new(big.Int).SetBytes(dataForEncrypt)
	c := encrypt(pub, mnum)

	// Pad bytes in the result if needed
	padLen := keyLen - len(c.Bytes())
	encryptedData := make([]byte, keyLen)
	for i := 0; i < padLen; i++ {
		dataForEncrypt[i] = 0x00
	}
	copy(encryptedData[padLen:], c.Bytes())

	return encryptedData, nil
}

func DecryptRSA(priv *PrivateKey, encryptedData []byte) ([]byte, error) {
	// check if the length of the encryptedData is correct
	lenPrivKey := (priv.N.BitLen() + 7) / 8
	if len(encryptedData) != lenPrivKey {
		return nil, fmt.Errorf("len(encryptedData)=%v, want keyLen=%v", len(encryptedData), lenPrivKey)
	}

	d := decrypt(priv, new(big.Int).SetBytes(encryptedData))

	dBytes := d.Bytes()

	// The most left pad '0x00' is omitted by Big.Int by default
	// We just add this pad manually
	dBytesAddPad := make([]byte, lenPrivKey)
	copy(dBytesAddPad[lenPrivKey-len(dBytes):], dBytes)

	if dBytesAddPad[0] != 0x00 {
		return nil, fmt.Errorf("m[0]=%v, want 0x00", dBytesAddPad[0])
	}
	if dBytesAddPad[1] != 0x02 {
		return nil, fmt.Errorf("m[1]=%v, want 0x02", dBytesAddPad[1])
	}

	endPadIndex := bytes.IndexByte(dBytesAddPad[2:], 0x00) + 2
	if endPadIndex < 2 {
		return nil, fmt.Errorf("end of padding not found")
	}

	return dBytesAddPad[endPadIndex+1:], nil
}
