package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/mikesmitty/edkey"
	"log"
	"os"
	"strings"
)

var (
	invokeCount = 0

	logger       *log.Logger
	errLogger    *log.Logger
	loggerPrefix = "[schism-lambda]  : "

	awsSession *session.Session
	awsRegion  string

	ssmClient       *ssm.SSM
	hostCaParamName string
	userCaParamName string

	ssmKmsKeyId string

	hostCA []byte
	userCA []byte
)

func init() {
	logger = log.New(os.Stdout, loggerPrefix, log.LstdFlags|log.Lmsgprefix)
	errLogger = log.New(os.Stderr, loggerPrefix, log.LstdFlags|log.Lmsgprefix)

	hostCaParamName = caParamName("host")
	userCaParamName = caParamName("user")

	ssmKmsKeyId = os.Getenv("SCHISM_CA_KMS_KEY_ID")

	ssmClient = newSsmClient()

	hostCA, userCA = loadCAsFromSSM()

	if hostCA == nil {
		hostCA = createCA()
		saveCAToSSM(hostCA, hostCaParamName)
	}
	if userCA == nil {
		userCA = createCA()
		saveCAToSSM(userCA, userCaParamName)
	}
}

func caParamName(caType string) string {
	lookupKey := fmt.Sprintf("SCHISM_%s_CA_PARAM_NAME", strings.ToUpper(caType))
	caParamName, keyFound := os.LookupEnv(lookupKey)
	if !keyFound || len(caParamName) == 0 {
		caParamName = fmt.Sprintf("schism-%s-ca-key", strings.ToLower(caType))
	}
	return caParamName
}

func createCA() []byte {
	_, privKey, _ := ed25519.GenerateKey(nil)

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privKey),
	}
	return pem.EncodeToMemory(pemKey)
}

func saveCAToSSM(caContents []byte, caParamName string) {
	putParamInput := &ssm.PutParameterInput{
		Name:        aws.String(caParamName),
		Description: aws.String("CA Certificate used to sign ssh certificates"),
		Value:       aws.String(string(caContents)),
		Type:        aws.String("SecureString"),
	}
	if len(ssmKmsKeyId) > 0 {
		putParamInput.KeyId = aws.String(ssmKmsKeyId)
	}
	_, err := ssmClient.PutParameter(putParamInput)
	if err != nil {
		errLogger.Printf("Error: %s Unable to save data to SSM", err.Error())
	}
}

func loadCAFromSSM(paramName string) []byte {
	ssmOutput, err := ssmClient.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		errLogger.Printf("Error: %s %s", err.Error(), paramName)
		return nil
	}
	return []byte(ssmOutput.String())
}

func loadCAsFromSSM() ([]byte, []byte) {
	var host = loadCAFromSSM(hostCaParamName)
	var user = loadCAFromSSM(userCaParamName)
	return host, user
}

func newSsmClient() *ssm.SSM {
	awsRegion = os.Getenv("AWS_REGION")
	awsSession = session.Must(session.NewSession())
	return ssm.New(awsSession, aws.NewConfig().WithRegion(awsRegion))
}

func LambdaHandler() (int, error) {
	invokeCount = invokeCount + 1
	logger.Printf("Region: `%s'", awsRegion)
	return invokeCount, nil
}

func main() {
	lambda.Start(LambdaHandler)
}
