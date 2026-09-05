package aesutil

// ruleid: crypto-ecb-mode-go
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return nil
}

// ok: crypto-ecb-mode-go
func NewGCM(b cipher.Block) (cipher.AEAD, error) {
	return nil, nil
}
