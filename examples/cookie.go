package main

import (
	"fmt"
	"html"

	"github.com/coscms/webx"
)

var cookieName = "cookie"

var notice = `
<div>%v</div>
`
var form = `
<form method="POST" action="update">
  {{XsrfFormHtml}}
  <div class="field">
    <label for="cookie"> Set a cookie: </label>
    <input id="cookie" name="cookie"> </input>
  </div>

  <input type="submit" value="Submit"></input>
  <input type="submit" name="submit" value="Delete"></input>
</form>
`

type CookieAction struct {
	*webx.Action

	index  webx.Mapper `webx:"/"`
	update webx.Mapper `webx:"/update"`
}

func (this *CookieAction) Index() {
	cookie, _ := this.GetCookie(cookieName)
	var top string
	if cookie == nil {
		top = fmt.Sprintf(notice, "The cookie has not been set")
	} else {
		var val = html.EscapeString(cookie.Value)
		top = fmt.Sprintf(notice, "The value of the cookie is '"+val+"'.")
	}
	this.RenderString(top + form)
}

func (this *CookieAction) Update() {
	if this.GetString("submit") == "Delete" {
		this.SetCookie(webx.NewCookie(cookieName, "", -1))
	} else {
		this.SetCookie(webx.NewCookie(cookieName, this.GetString("cookie"), 0))
	}
	this.Redirect("/", 301)
}

func main() {
	webx.AddAction(&CookieAction{})
	webx.Run("0.0.0.0:9999")
}
