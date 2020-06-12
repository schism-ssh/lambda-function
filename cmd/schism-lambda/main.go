package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"

	"src.doom.fm/schism/commonLib"
	"src.doom.fm/schism/commonLib/protocol"

	"src.doom.fm/schism/lambda-function/internal"
	"src.doom.fm/schism/lambda-function/internal/cloud"
	"src.doom.fm/schism/lambda-function/internal/crypto"
)

type caPairs map[string]*crypto.EncodedCaPair

var (
	invokeCount = 0

	logger    *log.Logger
	errLogger *log.Logger

	awsRegion    string
	schismConfig cloud.SchismConfig

	keyPairs caPairs
)

func init() {
	logger = internal.SchismLog(os.Stdout)
	errLogger = internal.SchismLog(os.Stderr)

	schismConfig.LoadEnv()

	awsRegion = os.Getenv("AWS_REGION")
}

func caKeysInit(ssmSvc ssmiface.SSMAPI) (err error) {
	hostParamName := fmt.Sprintf("%s-%s", schismConfig.CaParamPrefix, protocol.HostCertificate)
	hostKeyPair, err := cloud.LoadCAFromSSM(ssmSvc, hostParamName)
	if err != nil {
		hostKeyPair, err = crypto.CreateCA()
		if err != nil {
			return
		}
		err = cloud.SaveCAToSSM(ssmSvc, hostKeyPair, hostParamName, schismConfig.CaSsmKmsKeyId)
		if err != nil {
			return
		}
	}
	userParamName := fmt.Sprintf("%s-%s", schismConfig.CaParamPrefix, protocol.UserCertificate)
	userKeyPair, err := cloud.LoadCAFromSSM(ssmSvc, userParamName)
	if err != nil {
		userKeyPair, err = crypto.CreateCA()
		if err != nil {
			return
		}
		err = cloud.SaveCAToSSM(ssmSvc, userKeyPair, userParamName, schismConfig.CaSsmKmsKeyId)
		if err != nil {
			return
		}
	}
	keyPairs = caPairs{
		string(protocol.HostCertificate): hostKeyPair,
		string(protocol.UserCertificate): userKeyPair,
	}
	return
}

func LambdaHandler(requestEvent protocol.RequestSSHCertLambdaPayload) (protocol.RequestSSHCertLambdaResponse, error) {
	ssmClient := commonLib.SSMClient(awsRegion)
	if err := caKeysInit(ssmClient); err != nil {
		errLogger.Printf("Error initializing the CA keys: %v", err.Error())
	}

	invokeCount = invokeCount + 1
	response := protocol.RequestSSHCertLambdaResponse{}
	logger.Printf("Processing %s cert generation event\n", requestEvent.CertificateType)
	logger.Printf("Requested Identity: %s\n", requestEvent.Identity)
	logger.Printf("Requested Principals: %s\n", requestEvent.Principals)
	processEvent(requestEvent, &response)
	return response, nil
}

func processEvent(event protocol.RequestSSHCertLambdaPayload, out *protocol.RequestSSHCertLambdaResponse) {
	var certType uint32
	var signer ssh.Signer
	var err error
	if event.CertificateType == protocol.HostCertificate {
		certType = ssh.HostCert
		signer, err = keyPairs[string(protocol.HostCertificate)].Signer()
	} else if event.CertificateType == protocol.UserCertificate {
		certType = ssh.UserCert
		signer, err = keyPairs[string(protocol.UserCertificate)].Signer()
	} else {
		errLogger.Panicf("unknown CertificateType (%s) requested", event.CertificateType)
	}
	if err != nil {
		errLogger.Panicf("%s\nerror parsing ssh.Signer from (%s)keyPair", err, event.CertificateType)
	}
	out.LookupKey = string(protocol.GenerateLookupKey(event.Identity, event.Principals))
	signedCert := eventSignCertificates(event, certType, err, signer)
	err = eventUploadResults(event, signedCert)
	if err != nil {
		errLogger.Panicf("%s\nerror saving certificates to s3", err)
	}
}

func eventUploadResults(event protocol.RequestSSHCertLambdaPayload, signedCert *ssh.Certificate) error {
	s3Svc := commonLib.S3Client(awsRegion)
	marshaledCert := crypto.MarshalSignedCert(signedCert)
	oppositeCA := event.CertificateType.OppositeCA()
	s3OppositeCaCert := &protocol.CAPublicKeyS3Object{
		CertificateType: oppositeCA,
		AuthorizedKey:   keyPairs[string(oppositeCA)].AuthorizedKey,
	}
	s3Cert := &protocol.SignedCertificateS3Object{
		CertificateType:             event.CertificateType,
		IssuedOn:                    time.Unix(int64(signedCert.ValidAfter), 0),
		Identity:                    event.Identity,
		Principals:                  event.Principals,
		ValidityInterval:            event.ValidityInterval,
		RawSignedCertificate:        marshaledCert,
		OppositePublicCA:            s3OppositeCaCert.ObjectKey(schismConfig.CertsS3Prefix),
		SignedCertificateEncryption: nil,
	}
	objKey, err := cloud.SaveS3Object(s3Svc, schismConfig, s3Cert)
	if err != nil {
		return err
	} else {
		logger.Printf("Saved Certificate to '%s'", objKey)
	}
	objKey, err = cloud.SaveS3Object(s3Svc, schismConfig, s3OppositeCaCert)
	if err != nil {
		return err
	} else {
		logger.Printf("Saved CA Authorized Key to '%s'", objKey)
	}
	return nil
}

func eventSignCertificates(event protocol.RequestSSHCertLambdaPayload, certType uint32, err error, signer ssh.Signer) *ssh.Certificate {
	myReq := &crypto.SigningReq{
		PublicKey:  []byte(event.PublicKey),
		CertType:   certType,
		Identity:   event.Identity,
		Principals: event.Principals,
		TTL:        event.ValidityInterval,
	}
	signedCert, err := crypto.Sign(myReq, signer)
	if err != nil {
		errLogger.Panicf("%s\nCert Signing went wrong, see logs for details", err)
	}
	return signedCert
}

func main() {
	lambda.Start(LambdaHandler)
}
