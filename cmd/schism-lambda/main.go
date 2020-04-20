package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"

	"src.doom.fm/schism/commonLib"
	"src.doom.fm/schism/commonLib/protocol"

	"src.doom.fm/schism/lambda-function/internal"
	"src.doom.fm/schism/lambda-function/internal/cloud"
	"src.doom.fm/schism/lambda-function/internal/crypto"
)

var (
	invokeCount = 0

	logger    *log.Logger
	errLogger *log.Logger

	awsRegion     string
	caParamPrefix string
	ssmKmsKeyId   string

	hostKeyPair *crypto.CaSshKeyPair
	userKeyPair *crypto.CaSshKeyPair
)

func init() {
	logger = internal.SchismLog(os.Stdout)
	errLogger = internal.SchismLog(os.Stderr)

	caParamPrefix = cloud.CaParamPrefix()

	ssmKmsKeyId = os.Getenv("SCHISM_CA_KMS_KEY_ID")
	awsRegion = os.Getenv("AWS_REGION")
}

func caKeysInit(ssmSvc ssmiface.SSMAPI) (err error) {
	hostParamName := fmt.Sprintf("%s-host", caParamPrefix)
	hostKeyPair, err = cloud.LoadCAFromSSM(ssmSvc, hostParamName)
	if err != nil {
		hostKeyPair, err = crypto.CreateCA()
		if err != nil {
			return
		}
		err = cloud.SaveCAToSSM(ssmSvc, hostKeyPair, hostParamName, ssmKmsKeyId)
		if err != nil {
			return
		}
	}
	userParamName := fmt.Sprintf("%s-user", caParamPrefix)
	userKeyPair, err = cloud.LoadCAFromSSM(ssmSvc, userParamName)
	if err != nil {
		userKeyPair, err = crypto.CreateCA()
		if err != nil {
			return
		}
		err = cloud.SaveCAToSSM(ssmSvc, userKeyPair, userParamName, ssmKmsKeyId)
		if err != nil {
			return
		}
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
	if event.CertificateType == "host" {
		out.LookupKey = "HOST_LOOKUP_KEY"
	} else {
		out.LookupKey = "USER_LOOKUP_KEY"
	}
}

func main() {
	lambda.Start(LambdaHandler)
}
