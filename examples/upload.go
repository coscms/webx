package main

import (
	"github.com/coscms/webx"
)

var page = `
<html>
<head><title>Multipart Test</title></head>
<body>
<form action="/" enctype="multipart/form-data" method="POST">

<label for="file"> Please select a File </label>
<input id="file" type="file" name="file"/>
<br>
<label for="input1"> Please write some text </label>
<input id="input1" type="text" name="input1"/>
<br>
<label for="input2"> Please write some more text </label>
<input id="input2" type="text" name="input2"/>
<br>
<input type="submit" name="Submit" value="Submit"/>
</form>
</body>
</html>
`

type MainAction struct {
	*webx.Action

	upload webx.Mapper `webx:"/"`

	Id     int
	Input1 string
	Input2 string
}

func (c *MainAction) Init() {
	c.Option.CheckXsrf = false
}

func (c *MainAction) Upload() {
	if c.Method() == "GET" {
		c.Write(page)
	} else if c.Method() == "POST" {
		savefile := "./a"
		c.SaveToFile("file", savefile)

		c.Write("<p>input1: %v </p>", c.Input1)
		c.Write("<p>input2: %v </p>", c.Input2)
		c.Write("<p>file: %v</p>", savefile)
	}
}

func main() {
	webx.AddAction(&MainAction{})
	webx.Run("0.0.0.0:9999")
}
