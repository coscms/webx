package main

import (
	"fmt"

	"github.com/coscms/webx"
)

var page = `
<html>
<head><title>Multipart Test</title></head>
<body>
<form action="/" method="POST">
<label for="input1"> Please write some text </label>
<input id="input1" type="text" name="inputs"/>
<br>
<label for="input2"> Please write some more text </label>
<input id="input2" type="text" name="inputs"/>
<br>
<input type="submit" name="Submit" value="Submit"/>
</form>
</body>
</html>
`

type MainAction struct {
	*webx.Action

	upload webx.Mapper `webx:"/"`

	Inputs []string
}

func (c *MainAction) Init() {
	c.Option.CheckXsrf = false
}

func (c *MainAction) Upload() {
	if c.Method() == "GET" {
		c.Write(page)
	} else if c.Method() == "POST" {
		output := ""
		for i, input := range c.Inputs {
			output += fmt.Sprintf("input %v: %v <br />", i, input)
		}
		c.Write(output)
	}
}

func main() {
	webx.AddAction(&MainAction{})
	webx.Run("0.0.0.0:9999")
}
