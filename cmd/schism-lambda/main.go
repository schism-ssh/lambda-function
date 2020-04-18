package main

import (
	"log"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"src.doom.fm/schism/commonLib"
	"src.doom.fm/schism/commonLib/protocol"
	"src.doom.fm/schism/lambda-function/internal"
	"src.doom.fm/schism/lambda-function/internal/cloud"
)

var (
	invokeCount = 0

	logger       *log.Logger
	errLogger    *log.Logger
	loggerPrefix = "[schism-lambda] : "

	awsRegion string

	hostCaParamName string
	userCaParamName string

	ssmKmsKeyId string

	hostCA []byte
	userCA []byte
)

func init() {
	logger = log.New(os.Stdout, loggerPrefix, log.LstdFlags|log.Lmsgprefix)
	errLogger = log.New(os.Stderr, loggerPrefix, log.LstdFlags|log.Lmsgprefix)

	hostCaParamName = internal.CaParamName("host")
	userCaParamName = internal.CaParamName("user")

	ssmKmsKeyId = os.Getenv("SCHISM_CA_KMS_KEY_ID")
	awsRegion = os.Getenv("AWS_REGION")
}

func handlerInit() {
	invokeCount = invokeCount + 1
	var errs []error
	ssmClient := commonLib.SSMClient(awsRegion)
	hostCA, userCA, errs = cloud.LoadCAsFromSSM(ssmClient, &cloud.CaParamNames{
		Host: hostCaParamName,
		User: userCaParamName,
	})
	if len(errs) > 0 {
		for _, err := range errs {
			if err == nil {
				continue
			}
			errLogger.Printf("Error: %s", err.Error())
		}
	}
	if hostCA == nil {
		hostCA = internal.CreateCA()
		if err := cloud.SaveCAToSSM(ssmClient, hostCA, hostCaParamName, ssmKmsKeyId); err != nil {
			errLogger.Printf("Error: %s Unable to save data to SSM", err.Error())
		}
	}
	if userCA == nil {
		userCA = internal.CreateCA()
		if err := cloud.SaveCAToSSM(ssmClient, userCA, userCaParamName, ssmKmsKeyId); err != nil {
			errLogger.Printf("Error: %s Unable to save data to SSM", err.Error())
		}
	}
}

func LambdaHandler(requestEvent protocol.RequestSSHCertLambdaPayload) (protocol.RequestSSHCertLambdaResponse, error) {
	handlerInit()
	response := protocol.RequestSSHCertLambdaResponse{}
	logger.Printf("Processing %s cert generation event\n", requestEvent.CertificateType)
	logger.Printf("Requested Identity: %s\n", requestEvent.Identity)
	logger.Printf("Requested Principals: %s\n", requestEvent.Principals)
	processEvent(requestEvent, &response)
	return response, nil
}

func processEvent(event protocol.RequestSSHCertLambdaPayload, out *protocol.RequestSSHCertLambdaResponse) {
	switch event.CertificateType {
	case "host":
		out.LookupKey = "HOST_LOOKUP_KEY"
	case "user":
		out.LookupKey = "USER_LOOKUP_KEY"
	default:
		out.LookupKey = "ERROR"

	}
}

func main() {
	lambda.Start(LambdaHandler)
}
