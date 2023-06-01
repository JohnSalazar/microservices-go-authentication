package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/oceano-dev/microservices-go-common/helpers"
	"github.com/stretchr/testify/assert"
)

func BenchmarkGenerateCertificateAuthority(b *testing.B) {
	for i := 0; i < b.N; i++ {
		certificatesService.GenerateCertificateAuthority()
	}
}

func TestGenerateCertificateAuthority(t *testing.T) {
	byteCA, keyCA, err := certificatesService.GenerateCertificateAuthority()

	assert.NoError(t, err)
	assert.NotNil(t, byteCA)
	assert.NotNil(t, keyCA)
}

func TestGenerateCertificateHost(t *testing.T) {
	byteCA, keyCA, errCA := certificatesService.GenerateCertificateAuthority()
	certCA, errCertCA := x509.ParseCertificate(byteCA)

	byteCert, keyCert, err := certificatesService.GenerateCertificateHost(certCA, keyCA)

	assert.NotNil(t, byteCA)
	assert.NotNil(t, keyCA)
	assert.NoError(t, errCA)
	assert.NotNil(t, certCA)
	assert.NoError(t, errCertCA)
	assert.NotNil(t, byteCert)
	assert.NotNil(t, keyCert)
	assert.NoError(t, err)
}

func TestCreateCertificateCAPEM(t *testing.T) {

	byteCA, _, errCA := certificatesService.GenerateCertificateAuthority()

	err := certificatesService.CreateCertificateCAPEM(byteCA)

	caPath, _ := certificatesServiceCommon.GetPathsCertificateCAAndKey()
	fileExists := helpers.FileExists(caPath)

	assert.NoError(t, errCA)
	assert.NotNil(t, byteCA)
	assert.NoError(t, err)
	assert.True(t, fileExists)
}

func TestCreateCertificateCAPrivateKeyPEM(t *testing.T) {
	certCAPrivateKey, errCAPrivateKey := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	err := certificatesService.CreateCertificateCAPrivateKeyPEM(certCAPrivateKey)

	_, certCAPrivateKeyPath := certificatesServiceCommon.GetPathsCertificateCAAndKey()
	fileExists := helpers.FileExists(certCAPrivateKeyPath)

	assert.NotNil(t, certCAPrivateKey)
	assert.NoError(t, errCAPrivateKey)
	assert.NoError(t, err)
	assert.True(t, fileExists)
}

func TestCreateCertificateHostPrivateKeyPEM(t *testing.T) {
	certPrivateKey, errPrivateKey := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	err := certificatesService.CreateCertificateHostPrivateKeyPEM(certPrivateKey)

	_, certPrivateKeyPath := certificatesServiceCommon.GetPathsCertificateHostAndKey()
	fileExists := helpers.FileExists(certPrivateKeyPath)

	assert.NotNil(t, certPrivateKey)
	assert.NoError(t, errPrivateKey)
	assert.NoError(t, err)
	assert.True(t, fileExists)
}

func TestCreateCertificateHostPEM(t *testing.T) {
	byteCA, keyCA, errCA := certificatesService.GenerateCertificateAuthority()
	certCA, errCertCA := x509.ParseCertificate(byteCA)

	byteCert, keyCert, errCert := certificatesService.GenerateCertificateHost(certCA, keyCA)

	err := certificatesService.CreateCertificateHostPEM(byteCert)

	hostPath, _ := certificatesServiceCommon.GetPathsCertificateHostAndKey()
	fileExists := helpers.FileExists(hostPath)

	assert.NotNil(t, byteCA)
	assert.NotNil(t, keyCA)
	assert.NoError(t, errCA)
	assert.NotNil(t, certCA)
	assert.NoError(t, errCertCA)
	assert.NotNil(t, byteCert)
	assert.NotNil(t, keyCert)
	assert.NoError(t, errCert)
	assert.NoError(t, err)
	assert.True(t, fileExists)
}
