package cloud

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"

	"src.doom.fm/schism/commonLib/protocol"
	schismCrypt "src.doom.fm/schism/lambda-function/internal/crypto"
)

func LoadCAFromSSM(ssmSvc ssmiface.SSMAPI, paramName string) (*schismCrypt.EncodedCaPair, error) {
	ssmOutput, err := ssmSvc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	rawCaPair := []byte(*ssmOutput.Parameter.Value)
	caPair := &schismCrypt.EncodedCaPair{}
	if err := json.Unmarshal(rawCaPair, caPair); err != nil {
		return nil, err
	}
	return caPair, nil

}

func SaveCAToSSM(ssmSvc ssmiface.SSMAPI, caPair *schismCrypt.EncodedCaPair, caParamName string, ssmKmsKeyId string) error {
	caPairJson, err := json.Marshal(caPair)
	if err != nil {
		return err
	}
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

func SaveS3Object(s3Svc s3iface.S3API, config SchismConfig, s3Object protocol.S3Object) (string, error) {
	jsonBody, err := json.Marshal(s3Object)
	if err != nil {
		return "", err
	}

	md5Bytes := md5.Sum(jsonBody)
	contentMd5 := base64.StdEncoding.EncodeToString(md5Bytes[:])

	objectKey := s3Object.ObjectKey(config.CertsS3Prefix)
	putObjectInput := s3.PutObjectInput{
		Body:       bytes.NewReader(jsonBody),
		Bucket:     aws.String(config.CertsS3Bucket),
		Key:        aws.String(objectKey),
		ContentMD5: aws.String(contentMd5),
	}
	_, err = s3Svc.PutObject(&putObjectInput)
	if err != nil {
		return "", err
	}
	return objectKey, nil
}
