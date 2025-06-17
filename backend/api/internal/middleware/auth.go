package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/valyala/fasthttp"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// get user id from context

		token, err := GetTokenFromAuthorizationHeader(c)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		userId, tokenType, err := TokenCheck(token, s.config.Auth.JWTkey)
		if err != nil {
			s.logger.Error(err.Error())
			if errors.Is(err, jwt.ErrTokenExpired) {
				ctx.Error(err.Error(), fasthttp.StatusUnauthorized)
				return
			}
			ctx.Error(err.Error(), fasthttp.StatusBadRequest)
			return
		}

		/*

			userID, err := GetUserIDFromGinContext(c)
			if err != nil {
				logger.Error("%v", err)
				c.AbortWithStatus(500)
				return
			}

			// check if user in database
			exists, err := models.CheckIfUserExistsByID(userID)
			if err != nil {
				logger.Error("%v", err)
				c.AbortWithStatus(500)
				return
			}

			// call c.Next if user in database
			// else response with 401
			if exists {
				c.Next()
				return
			} else {
				c.JSON(401, gin.H{"error": "User not authorized"})
				c.Abort()
				return
			}

		*/
	}
}
