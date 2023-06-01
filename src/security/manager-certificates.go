package security

import (
	"crypto/x509"
	"errors"
	"time"

	"authentication/src/services"

	"github.com/oceano-dev/microservices-go-common/config"
	"github.com/oceano-dev/microservices-go-common/helpers"
	common_service "github.com/oceano-dev/microservices-go-common/services"
)

type managerCertificates struct {
	config         *config.Config
	service        services.CertificatesService
	common_service common_service.CertificatesService
}

var (
	certPath string
	keyPath  string
)

func NewManagerCertificates(
	config *config.Config,
	service services.CertificatesService,
	common_service common_service.CertificatesService,
) *managerCertificates {
	certPath, keyPath = common_service.GetPathsCertificateHostAndKey()
	return &managerCertificates{
		config:         config,
		service:        service,
		common_service: common_service,
	}
}

func (m *managerCertificates) VerifyCertificates() bool {
	if !helpers.FileExists(certPath) || !helpers.FileExists(keyPath) {
		err := m.newCertificate()

		return err == nil
	}

	cert, err := m.common_service.ReadCertificate()
	if err != nil {
		return false
	}

	if cert == nil || cert.NotAfter.AddDate(0, 0, -7).Before(time.Now().UTC()) {
		err := m.newCertificate()
		if err != nil {
			return false
		}

	}

	return true
}

func (m *managerCertificates) GetCertificateCA() error {
	return errors.New("not implemented")
}

func (m *managerCertificates) GetCertificate() error {
	return errors.New("not implemented")
}

func (m *managerCertificates) newCertificate() error {
	caBytes, caPrivateKey, err := m.service.GenerateCertificateAuthority()
	if err != nil {
		return err
	}

	err = m.service.CreateCertificateCAPEM(caBytes)
	if err != nil {
		return err
	}

	err = m.service.CreateCertificateCAPrivateKeyPEM(caPrivateKey)
	if err != nil {
		return err
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}

	hostBytes, hostPrivateKey, err := m.service.GenerateCertificateHost(caCert, caPrivateKey)
	if err != nil {
		return err
	}

	err = m.service.CreateCertificateHostPEM(hostBytes)
	if err != nil {
		return err
	}

	err = m.service.CreateCertificateHostPrivateKeyPEM(hostPrivateKey)
	if err != nil {
		return err
	}

	return nil
}
