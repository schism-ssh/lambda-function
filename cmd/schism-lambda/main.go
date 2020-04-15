package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"log"
	"os"
	"src.doom.fm/schism/commonLib"
	"src.doom.fm/schism/lambda-function/lib"
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

	hostCaParamName = lib.CaParamName("host")
	userCaParamName = lib.CaParamName("user")

	ssmKmsKeyId = os.Getenv("SCHISM_CA_KMS_KEY_ID")
	awsRegion = os.Getenv("AWS_REGION")
}

func handlerInit() {
	invokeCount = invokeCount + 1
	var errs []error
	ssmClient := commonLib.SSMClient(awsRegion)
	hostCA, userCA, errs = lib.LoadCAsFromSSM(ssmClient, &lib.CaParamNames{
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
		hostCA = lib.CreateCA()
		if err := lib.SaveCAToSSM(ssmClient, hostCA, hostCaParamName, ssmKmsKeyId); err != nil {
			errLogger.Printf("Error: %s Unable to save data to SSM", err.Error())
		}
	}
	if userCA == nil {
		userCA = lib.CreateCA()
		if err := lib.SaveCAToSSM(ssmClient, userCA, userCaParamName, ssmKmsKeyId); err != nil {
			errLogger.Printf("Error: %s Unable to save data to SSM", err.Error())
		}
	}
}

func LambdaHandler() (int, error) {
	handlerInit()
	logger.Printf("Region: `%s'", awsRegion)
	return invokeCount, nil
}

func main() {
	lambda.Start(LambdaHandler)
}
