package models

import (
	"crypto/ecdsa"
	"time"
)

type ECDSAPrivateKey struct {
	PrivateKey *ecdsa.PrivateKey `json:"privateKey"`
	Alg        string            `json:"alg"`
	Kid        string            `json:"kid"`
	Use        string            `json:"use"`
	ExpiresAt  time.Time         `json:"expires_at"`
}
