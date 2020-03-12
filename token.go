package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type tokenBody struct {
	userID     int32  `json:"id"`
	username   string `json:"username"`
	clientName string `json:"clientName"`
	client     string `json:"client"`
	timezone   string `json:"timezone"`
	currency   string `json:"currency"`
	roleID     int32  `json:"role"`
	issueDate  int64  `json:"issueDate"`
}

func (t *tokenBody) GetUserID() int32 {
	if t == nil {
		return 0
	}
	return t.userID
}

func (t *tokenBody) GetUsername() string {
	if t == nil {
		return ""
	}
	return t.username
}

func (t *tokenBody) GetClientName() string {
	if t == nil {
		return ""
	}
	return t.clientName
}

func (t *tokenBody) GetClient() string {
	if t == nil {
		return ""
	}
	return t.client
}

func (t *tokenBody) GetTimeZone() string {
	if t == nil {
		return ""
	}
	return t.timezone
}

func (t *tokenBody) GetCurrency() string {
	if t == nil {
		return ""
	}
	return t.currency
}

func (t *tokenBody) GetRoleID() int32 {
	if t == nil {
		return 0
	}
	return t.roleID
}

func (t *tokenBody) GetIssueDate() int64 {
	if t == nil {
		return 0
	}
	return t.issueDate
}

//accepts decoded token string and returns token object
func createToken(token string) (*tokenBody, error) {
	var t tokenBody

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
func CreateTokenFromEncodedJWT(encodedJWT string) (*tokenBody, error) {
	encodedTokenArray := strings.Split(encodedJWT, ".")
	if len(encodedTokenArray) != 3 {
		return nil, errors.New("invalid token")
	}
	return CreateTokenFromEncodedString(encodedTokenArray[1])
}

//accepts encoded token string and returns token object
func CreateTokenFromEncodedString(encodedToken string) (*tokenBody, error) {
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
