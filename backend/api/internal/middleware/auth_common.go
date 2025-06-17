package middleware

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"time"
)

const (
	TokenAccess     = "TokenAccess"
	TokenRefresh    = "TokenRefresh"
	TokenDisposable = "TokenDisposable"
	TokenTelegram   = "TokenTelegram"
	TokenUser       = "TokenUser"
	TokenDriver     = "TokenDriver"

	queryArgName = "lacerta_auth_token"
)

func HashAndSalt(pass string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func ComparePasswords(passHash string, pass string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(passHash), []byte(pass))

	return err == nil
}

func TokenNew(hmacSecretKey string, userId models.UserId, expAccess int64, tokenType string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type":   tokenType,
		"userId": userId,
		"exp":    expAccess,
	})
	tokenStr, err := token.SignedString([]byte(hmacSecretKey))
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func TokenCheck(tokenStr string, hmacSecretKey string) (models.UserId, string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("nexpected signing method: %v", token.Header["alg"])
		}

		return []byte(hmacSecretKey), nil
	})
	if err != nil {
		if !errors.Is(err, jwt.ErrTokenExpired) {
			return 0, "", err
		}
	}

	if claims, ok := token.Claims.(jwt.MapClaims); !ok {
		return 0, "", errors.New("error get jwt.MapClaims")
	} else {
		var userId models.UserId
		var tokenType string

		if v, ok := claims["userId"]; !ok {
			return 0, "", errors.New("no userId field")
		} else {
			userId = models.UserId(v.(float64))
		}

		if v, ok := claims["type"]; !ok {
			return 0, "", errors.New("no type field")
		} else {
			tokenType = v.(string)
		}

		// передаём err чтобы ещё раз можно было проверить устарел токен или нет, другие ошибки сюда не попадут
		return userId, tokenType, err
	}
}

func PasswordCheck(configMaxTimePass, configMinTimePass uint64, passwordTimeUpdate uint64) error {
	tmNow := uint64(time.Now().Unix())

	if configMaxTimePass != 0 && passwordTimeUpdate+configMaxTimePass < tmNow {
		return errors.New("your password has expired")
	}

	if configMinTimePass != 0 && passwordTimeUpdate+configMinTimePass > tmNow {
		return errors.New("the minimum period has not passed")
	}

	return nil
}
