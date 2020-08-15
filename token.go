package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type Token struct {
	UserID     int32  `json:"id"`
	Username   string `json:"username"`
	ClientName string `json:"clientName"`
	Client     string `json:"client"`
	Timezone   string `json:"timezone"`
	Currency   string `json:"currency"`
	RoleID     int32  `json:"role"`
	IssueDate  int64  `json:"issueDate"`
}

func (t *Token) Validate() bool {
	if t.UserID != 0 &&
		len(t.Username) != 0 &&
		len(t.ClientName) != 0 &&
		len(t.Currency) != 0 &&
		len(t.Client) != 0 &&
		len(t.Timezone) != 0 &&
		t.RoleID != 0 {
		return true
	}
	return false
}

//create json from instance
func (t *Token) Stringify() (string, error) {
	tj, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	return string(tj), nil
}

//update issueDate
func (t *Token) UpdateToken(newTimeStamp int64) {
	t.IssueDate = newTimeStamp
}

//accepts decoded token string and returns token object
func createToken(token string) (*Token, error) {
	var t Token

	err := json.Unmarshal([]byte(token), &t)
	if err != nil {
		return &t, err
	}

	return &t, nil
}

// Base64Decode takes in a base 64 encoded string and returns the //actual string or an error of it fails to decode the string
func base64Decode(src string) (string, error) {
	if len(src) == 0 {
		return "", errors.New("cannot decode empty string")
	}

	data, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

//accepts jwt stored in cookie and returns token object
func CreateTokenFromEncodedJWT(encodedJWT string) (*Token, error) {
	encodedTokenArray := strings.Split(encodedJWT, ".")
	if len(encodedTokenArray) != 3 {
		return nil, errors.New("invalid token")
	}
	return CreateTokenFromEncodedString(encodedTokenArray[1])
}

//accepts encoded token string and returns token object
func CreateTokenFromEncodedString(encodedToken string) (*Token, error) {
	decodedToken, err := base64Decode(encodedToken)
	if err != nil {
		return nil, err
	}

	token, err := createToken(decodedToken)
	if err != nil {
		return nil, err
	}
	return token, nil
}
