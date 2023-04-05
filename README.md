# csrf
a gin csrf middleware

## install
```shell
go get github.com/dev-shao/csrf
```

## Quick start
```go
package main

import (
	"github.com/dev-shao/csrf"
	"github.com/gin-gonic/gin"
)

func main() {
    router := gin.Default()
	//add middleware
	router.Use(csrf.Middleware())
	//load templates
	router.LoadHTMLGlob("templates/*")
	router.GET("/form", func(context *gin.Context) { 
		//get csrf token
		csrfToken := csrf.GetCSRFToken(context)
		//get csrf form input element 
		csrfHtml := csrf.GetCSRFHTML(context)
		ctx := map[string]interface{}{
			"csrfHtml":  csrfHtml,
			"csrfToken": csrfToken,
		}
		context.HTML(200, "form.html", ctx)
	})
	router.POST("/form", func(context *gin.Context) {
        //If csrf token verify fail, Request will be aborted
	})
	router.Run()
}
```
form.html
```html
<form action="/form" method="post">
    {{.csrfHtml}}
    ...
</form>
```
by ajax to send token
```javascript
$.post("/post", {
    "csrftoken":"{{.csrfToken}}",
    ...
    }
)
```
by request header to send token
```javascript
headers = {
    "X-CSRFToken":"{{.csrfToken}}",
    ...
}
```
> remember add "X-CSRFToken" to cors allow header