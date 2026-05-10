package authservice

import (
	"net/http"

	"github.com/Ayush10/authentication-service/pkg/jwtvalidator"
	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

func HTTPMiddleware(verifier *jwtvalidator.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return verifier.Middleware(next) }
}

func GinMiddleware(verifier *jwtvalidator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := verifier.ValidateFromRequest(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set("authservice", claims)
		c.Request = c.Request.WithContext(jwtvalidator.WithClaims(c.Request.Context(), claims))
		c.Next()
	}
}

func ChiMiddleware(verifier *jwtvalidator.Validator) func(http.Handler) http.Handler {
	return HTTPMiddleware(verifier)
}

func EchoMiddleware(verifier *jwtvalidator.Validator) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, err := verifier.ValidateFromRequest(c.Request())
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}
			c.Set("authservice", claims)
			return next(c)
		}
	}
}

func FiberMiddleware(verifier *jwtvalidator.Validator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		req, err := http.NewRequest(http.MethodGet, "/", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", c.Get("Authorization"))
		claims, err := verifier.ValidateFromRequest(req)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}
		c.Locals("authservice", claims)
		return c.Next()
	}
}
