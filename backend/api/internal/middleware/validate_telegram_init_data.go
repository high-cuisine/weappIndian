package middleware

import (
	"BlessedApi/pkg/logger"
	"errors"
	"log" // Добавляем стандартный логгер
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	ContextUserIDKey   = "user_id"
	InitDataExpiration = 24 * time.Hour
)

var telegramBotToken string

func init() {
	var ok bool
	telegramBotToken, ok = os.LookupEnv("TOKEN")
	if !ok {
		logger.Fatal("unable to get telegram bot token from environment")
	}
}

func GetUserIDFromGinContext(c *gin.Context) (int64, error) {
	// Get user_id from middleware
	userIDAny, ok := c.Get(ContextUserIDKey)
	if !ok {
		return 0, logger.WrapError(errors.New("user_id not in GIN context"), "")
	}

	userIDInt, ok := userIDAny.(int64)
	if !ok {
		return 0, logger.WrapError(errors.New("unable to cast user_id value to int"), "")
	}

	log.Printf("GetUserIDFromGinContext - checking context keys: %+v", c.Keys)
	logger.Warn(strconv.FormatInt(userIDInt, 10))

	return userIDInt, nil
}

func GetTokenFromAuthorizationHeader(c *gin.Context) (string, error) {
	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		return "", errors.New("authorization header is empty")
	}

	token := strings.Split(authorizationHeader[:], " ")
	if len(token) != 2 || token[0] != "Bearer" {
		return "", errors.New("authorization not Bearer format")
	}

	return token[1], nil
}
