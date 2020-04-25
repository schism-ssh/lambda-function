package cloud

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"

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
