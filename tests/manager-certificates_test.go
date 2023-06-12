package tests

import (
	"testing"

	"github.com/JohnSalazar/microservices-go-common/helpers"
	"github.com/stretchr/testify/assert"
)

func TestVerifyCertificateSuccess(t *testing.T) {

	DeleteFolder()
	helpers.CreateFolder(myConfig.Folders)

	isValid := managerCertificates.VerifyCertificates()

	assert.True(t, isValid)
}
