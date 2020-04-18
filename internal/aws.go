package internal

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

type CaParamNames struct {
	Host string
	User string
}

func LoadCAFromSSM(ssmSvc ssmiface.SSMAPI, paramName string) ([]byte, error) {
	ssmOutput, err := ssmSvc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	return []byte(*ssmOutput.Parameter.Value), nil
}

func LoadCAsFromSSM(ssmSvc ssmiface.SSMAPI, params *CaParamNames) (host []byte, user []byte, errs []error) {
	errs = make([]error, 2)
	if host, errs[0] = LoadCAFromSSM(ssmSvc, params.Host); errs[0] != nil {
		host = nil
	}
	if user, errs[1] = LoadCAFromSSM(ssmSvc, params.User); errs[1] != nil {
		user = nil
	}
	return
}

func SaveCAToSSM(ssmSvc ssmiface.SSMAPI, caContents []byte, caParamName string, ssmKmsKeyId string) error {
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
	return err
}
