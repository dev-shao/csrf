package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"html/template"
	"net/http"
	"strings"
)

const encodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz_-"

var encoding *base64.Encoding = base64.NewEncoding(encodeChars).WithPadding(base64.NoPadding)

var ErrNotImple = errors.New("This function is not implemented")

var UseSession bool = false
var CSRFKey string = "CSRFToken"
var CSRFHeader string = "X-CSRFToken"
var CSRFCookieAge int = 86400

func Middleware() gin.HandlerFunc {
	return func(context *gin.Context) {
		token := getToken(context)
		if len(token) != 32 {
			token = newToken()
			setToken(context, token)
		}
		context.Set("CSRF_TOKEN", encryptToken(token))

		switch context.Request.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete:
			requestToken := getRequestToken(context)
			if !verifyToken(requestToken, token) {
				if gin.Mode() == gin.DebugMode {
					context.String(http.StatusForbidden, "CSRF verification failed! Request aborted.")
					context.Abort()
				} else {
					context.AbortWithStatus(http.StatusForbidden)
				}
				return
			}
		}
	}
}

// get unmask token
func GetCSRFToken(ctx *gin.Context) string {
	token := ctx.GetString("CSRF_TOKEN")
	if len(token) != 64 {
		token = getToken(ctx)
		if len(token) != 32 {
			token = newToken()
			setToken(ctx, token)
		}
		token = encryptToken(token)
		ctx.Set("CSRF_TOKEN", token)
	}
	return token
}

func GetCSRFHTML(ctx *gin.Context) template.HTML {
	token := GetCSRFToken(ctx)
	return template.HTML(fmt.Sprintf(`<input type="hidden" name="csrftoken" value="%s">`, token))
}

// get unmask csrf token from cookie or session
func getToken(ctx *gin.Context) string {
	var token string
	if UseSession {
		panic(ErrNotImple)
	} else {
		token, _ = ctx.Cookie(CSRFKey)
	}
	return token
}

// set unmask token in cookie or session
func setToken(ctx *gin.Context, token string) {
	if UseSession {
		panic(ErrNotImple)
	} else {
		ctx.SetCookie(CSRFKey, token, CSRFCookieAge, "", "", false, false)
	}
}

// get mask csrf token from PostForm or Headers
func getRequestToken(ctx *gin.Context) string {
	token := ctx.PostForm("csrftoken")
	if token == "" {
		token = ctx.GetHeader(CSRFHeader)
	}
	return token
}

// verify the mask token obtained from request and the original unmask toke
func verifyToken(requestToken, token string) bool {
	if len(requestToken) != 64 || len(token) != 32 {
		return false
	}
	return decryptToken(requestToken) == token
}

func rand_string(length int) string {
	buf := make([]byte, length)
	rand.Read(buf)
	return encoding.EncodeToString(buf)[:length]
}

// get 32 length random string token
func newToken() string {
	return rand_string(32)
}

// mask token,returns 64 length string
func encryptToken(secret string) string {
	salt := rand_string(32)
	cipher := make([]byte, 32)
	charsLength := len(encodeChars)
	for i := 0; i < 32; i++ {
		x := strings.IndexByte(encodeChars, secret[i])
		y := strings.IndexByte(encodeChars, salt[i])
		cipher[i] = encodeChars[(x+y)%charsLength]
	}
	return salt + string(cipher)
}

// unmask token, returns 32 length origin token
func decryptToken(token string) string {
	salt := token[:32]
	cipher := token[32:]
	secret := make([]byte, 32)
	charsLength := len(encodeChars)
	for i := 0; i < 32; i++ {
		x := strings.IndexByte(encodeChars, cipher[i])
		y := strings.IndexByte(encodeChars, salt[i])
		if x < y {
			secret[i] = encodeChars[charsLength+x-y]
		} else {
			secret[i] = encodeChars[x-y]
		}
	}
	return string(secret)
}
