package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/JohnSalazar/microservices-go-common/config"
	"github.com/JohnSalazar/microservices-go-common/helpers"
	common_services "github.com/JohnSalazar/microservices-go-common/services"
)

type CertificatesService interface {
	CreateCertificateCAPEM(caBytes []byte) error
	CreateCertificateCAPrivateKeyPEM(certCAPrivateKey *ecdsa.PrivateKey) error
	CreateCertificateHostPEM(hostBytes []byte) error
	CreateCertificateHostPrivateKeyPEM(certPrivateKey *ecdsa.PrivateKey) error
	GenerateCertificateAuthority() ([]byte, *ecdsa.PrivateKey, error)
	GenerateCertificateHost(ca *x509.Certificate, certCAPrivateKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error)
}

type certificatesService struct {
	config                   *config.Config
	commonCertificateService common_services.CertificatesService
}

func NewCertificatesServices(
	config *config.Config,
	commonCertificateService common_services.CertificatesService,
) *certificatesService {
	return &certificatesService{
		config:                   config,
		commonCertificateService: commonCertificateService,
	}
}

func (s *certificatesService) GenerateCertificateAuthority() ([]byte, *ecdsa.PrivateKey, error) {
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := s.generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	publicKey := caPrivateKey.PublicKey
	subjectKeyId, err := s.generateSubjectKeyID(publicKey)
	if err != nil {
		return nil, nil, err
	}

	streetAddress := fmt.Sprintf("%s, %s, %s",
		s.config.Company.Address,
		s.config.Company.AddressNumber,
		s.config.Company.AddressComplement,
	)

	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		SubjectKeyId: subjectKeyId,
		Subject: pkix.Name{
			Country:       []string{s.config.Company.Country},
			Organization:  []string{s.config.Company.Name},
			Locality:      []string{s.config.Company.Locality},
			Province:      []string{s.config.Company.Locality},
			StreetAddress: []string{streetAddress},
			PostalCode:    []string{s.config.Company.PostalCode},
		},
		NotBefore:                   time.Now().UTC(),
		NotAfter:                    time.Now().UTC().AddDate(3, 0, 0),
		KeyUsage:                    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage:          nil,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              false,
		DNSNames:                    nil,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"localhost"},
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return caBytes, caPrivateKey, nil
}

func (s *certificatesService) CreateCertificateCAPEM(caBytes []byte) error {
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPath, _ := s.commonCertificateService.GetPathsCertificateCAAndKey()
	err := helpers.CreateFile(caPEM, caPath)
	if err != nil {
		return err
	}

	return nil
}

func (s *certificatesService) CreateCertificateCAPrivateKeyPEM(certCAPrivateKey *ecdsa.PrivateKey) error {
	certCAPrivateKeyBytes, err := x509.MarshalECPrivateKey(certCAPrivateKey)
	if err != nil {
		return err
	}

	certCAPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certCAPrivateKeyBytes,
	})

	_, certCAPrivateKeyPath := s.commonCertificateService.GetPathsCertificateCAAndKey()
	err = helpers.CreateFile(certCAPrivateKeyPEM, certCAPrivateKeyPath)
	if err != nil {
		return err
	}

	return nil
}

func (s *certificatesService) GenerateCertificateHost(ca *x509.Certificate, certCAPrivateKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := s.generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	publicKey := certPrivateKey.PublicKey
	subjectKeyId, err := s.generateSubjectKeyID(publicKey)
	if err != nil {
		return nil, nil, err
	}

	host := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject:      pkix.Name{},
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Time{},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		UnknownExtKeyUsage:          nil,
		BasicConstraintsValid:       false,
		SubjectKeyId:                nil,
		DNSNames:                    nil,
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
		IPAddresses:                 []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	host.SerialNumber.Set(serialNumber)
	host.RawSubject = ca.RawSubject

	caExpiry := time.Now().Add(time.Until(ca.NotAfter))
	host.NotAfter = caExpiry

	host.SubjectKeyId = subjectKeyId
	host.DNSNames = ca.DNSNames
	host.URIs = ca.URIs

	hostBytes, err := x509.CreateCertificate(rand.Reader, &host, ca, &certPrivateKey.PublicKey, certCAPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return hostBytes, certPrivateKey, nil
}

func (s *certificatesService) CreateCertificateHostPrivateKeyPEM(certPrivateKey *ecdsa.PrivateKey) error {
	certPrivateKeyBytes, err := x509.MarshalECPrivateKey(certPrivateKey)
	if err != nil {
		return err
	}

	certPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certPrivateKeyBytes,
	})

	_, certPrivateKeyPath := s.commonCertificateService.GetPathsCertificateHostAndKey()
	err = helpers.CreateFile(certPrivateKeyPEM, certPrivateKeyPath)
	if err != nil {
		return err
	}

	return nil
}

func (s *certificatesService) CreateCertificateHostPEM(hostBytes []byte) error {
	hostPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: hostBytes,
	})

	hostPath, _ := s.commonCertificateService.GetPathsCertificateHostAndKey()
	err := helpers.CreateFile(hostPEM, hostPath)
	if err != nil {
		return err
	}

	return nil
}

func (s *certificatesService) generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	return serialNumber, nil
}

func (s *certificatesService) generateSubjectKeyID(publicKey ecdsa.PublicKey) ([]byte, error) {
	publicKeyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)

	hash := sha1.Sum(publicKeyBytes)

	return hash[:], nil
}
