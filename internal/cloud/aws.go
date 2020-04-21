package cloud

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"

	"src.doom.fm/schism/commonLib/protocol"
	"src.doom.fm/schism/lambda-function/internal/crypto"
)

func LoadCAFromSSM(ssmSvc ssmiface.SSMAPI, paramName string) (*crypto.EncodedCaPair, error) {
	ssmOutput, err := ssmSvc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	rawCaPair := []byte(*ssmOutput.Parameter.Value)
	caPair := &crypto.EncodedCaPair{}
	if err := json.Unmarshal(rawCaPair, caPair); err != nil {
		return nil, err
	}
	return caPair, nil

}

func SaveCAToSSM(ssmSvc ssmiface.SSMAPI, caPair *crypto.EncodedCaPair, caParamName string, ssmKmsKeyId string) error {
	caPairJson, err := json.Marshal(caPair)
	putParamInput := &ssm.PutParameterInput{
		Name:        aws.String(caParamName),
		Description: aws.String("CA Certificate used to sign ssh certificates"),
		Value:       aws.String(string(caPairJson)),
		Type:        aws.String("SecureString"),
	}
	if len(ssmKmsKeyId) > 0 {
		putParamInput.KeyId = aws.String(ssmKmsKeyId)
	}
	_, err = ssmSvc.PutParameter(putParamInput)
	return err
}

func SaveCertToS3(s3Svc s3iface.S3API, s3Bucket string, s3Object *protocol.SignedCertificateS3Object) (string, error) {
	lookupKey := LookupKey(s3Object.Identity, s3Object.Principals)
	objectKey := fmt.Sprintf("%ss/%s.json", s3Object.CertificateType, lookupKey)
	putObjectIn := &s3.PutObjectInput{
		Body:   nil,
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(objectKey),
	}
	_, err := s3Svc.PutObject(putObjectIn)
	if err != nil {
		return "", err
	}
	return objectKey, nil
}
