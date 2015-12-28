package main

import (
	"github.com/coscms/webx"
)

type MainAction struct {
	*webx.Action

	hello webx.Mapper `webx:"/(.*)" tmpl:"/index(_{page})" memo:"演示首页"`
}

func (c *MainAction) Hello(world string) {
	world += ": " + c.BuildUrl("hello?page=10", c)
	c.Write("hello %v", world)
}

func main() {
	webx.RootApp().AppConfig.SessionOn = false
	webx.AddRouter("/", &MainAction{})
	webx.Run("0.0.0.0:9999")
}
