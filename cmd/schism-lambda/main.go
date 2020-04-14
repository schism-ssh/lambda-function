package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
	"github.com/mikesmitty/edkey"
	"log"
	"os"
	"strings"
)

var (
	invokeCount = 0

	logger       *log.Logger
	errLogger    *log.Logger
	loggerPrefix = "[schism-lambda] : "

	awsSession *session.Session
	awsRegion  string

	hostCaParamName string
	userCaParamName string

	ssmKmsKeyId string

	hostCA []byte
	userCA []byte
)

func caParamName(caType string) string {
	lookupKey := fmt.Sprintf("SCHISM_%s_CA_PARAM_NAME", strings.ToUpper(caType))
	caParamName, keyFound := os.LookupEnv(lookupKey)
	if !keyFound || len(caParamName) == 0 {
		caParamName = fmt.Sprintf("schism-%s-ca-key", strings.ToLower(caType))
	}
	return caParamName
}

func init() {
	logger = log.New(os.Stdout, loggerPrefix, log.LstdFlags|log.Lmsgprefix)
	errLogger = log.New(os.Stderr, loggerPrefix, log.LstdFlags|log.Lmsgprefix)

	hostCaParamName = caParamName("host")
	userCaParamName = caParamName("user")

	ssmKmsKeyId = os.Getenv("SCHISM_CA_KMS_KEY_ID")
	awsRegion = os.Getenv("AWS_REGION")
}

func saveCAToSSM(ssmSvc ssmiface.SSMAPI, caContents []byte, caParamName string) {
	putParamInput := &ssm.PutParameterInput{
		Name:        aws.String(caParamName),
		Description: aws.String("CA Certificate used to sign ssh certificates"),
		Value:       aws.String(string(caContents)),
		Type:        aws.String("SecureString"),
	}
	if len(ssmKmsKeyId) > 0 {
		putParamInput.KeyId = aws.String(ssmKmsKeyId)
	}
	_, err := ssmSvc.PutParameter(putParamInput)
	if err != nil {
		errLogger.Printf("Error: %s Unable to save data to SSM", err.Error())
	}
}

func createCA() []byte {
	_, privKey, _ := ed25519.GenerateKey(nil)

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey),
	}
	return pem.EncodeToMemory(pemKey)
}

func loadCAFromSSM(ssmSvc ssmiface.SSMAPI, paramName string) []byte {
	ssmOutput, err := ssmSvc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		errLogger.Printf("Error: %s %s", err.Error(), paramName)
		return nil
	}
	return []byte(*ssmOutput.Parameter.Value)
}

func loadCAsFromSSM(ssmSvc ssmiface.SSMAPI) ([]byte, []byte) {
	var host = loadCAFromSSM(ssmSvc, hostCaParamName)
	var user = loadCAFromSSM(ssmSvc, userCaParamName)
	return host, user
}

func handlerInit() {
	invokeCount = invokeCount + 1

	awsSession = session.Must(session.NewSession())

	ssmClient := ssm.New(awsSession, aws.NewConfig().WithRegion(awsRegion))
	hostCA, userCA = loadCAsFromSSM(ssmClient)
	if hostCA == nil {
		hostCA = createCA()
		saveCAToSSM(ssmClient, hostCA, hostCaParamName)
	}
	if userCA == nil {
		userCA = createCA()
		saveCAToSSM(ssmClient, userCA, userCaParamName)
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
