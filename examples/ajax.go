package main

import (
	"fmt"
	"reflect"

	"github.com/coscms/webx"
)

var tmpl = `
<html>
<head>
<script src="https://code.jquery.com/jquery-1.11.1.min.js"></script>
<script>
function form() {
var name = $.trim($("#username").val());
    			var password = $.trim($("#password").val());
    			/*var user = {
    				username:name,
    				password:password
    			};*/

    			//var user = [name, password]
    			var user = {
    				"username":name,
    				"password":password
    			};

$.ajax({
        			url : "/login",
        			dataType : "json",
        			beforeSend: function(){
        				$(".login-btn").hide();
        				$(".login-load").show();
        			},
        			type : "post",
        			data:{"user":user},
        			success: function(data){
        				if(data.status == 0){
        					alert(data.msg);
        					$(".login-load").hide();
        					$(".login-btn").show();
        				}else{
        					$(".login-load").hide();
        					$(".login-btn").show();
        					window.location.href = "blog/list";
        				}
        			}
        		});
}

$(function(){
	$("#sub").click(form)
})
</script>
</head>
<body>
<form>
<input type="text" id="username"/>
<input type="password" id="password"/>
<input type="button" id="sub" value="登录"/>
</form>
</body>
</html>
`

type User struct {
	Username string
	Password string
}

type MainAction struct {
	*webx.Action

	home  webx.Mapper `webx:"/"`
	login webx.Mapper `webx:"/login"`
	User  User
}

func (c *MainAction) Home() error {
	return c.Write(tmpl)
}

func (c *MainAction) Login() error {
	fmt.Println("user:", c.User)
	forms := c.GetForm()
	for k, v := range forms {
		fmt.Println("--", k, "-- is", reflect.TypeOf(k))
		fmt.Println("--", v, "-- is", reflect.TypeOf(v))
	}
	return nil
}

func main() {
	webx.RootApp().AppConfig.CheckXsrf = false
	webx.RootApp().AppConfig.SessionOn = false
	webx.AddRouter("/", &MainAction{})
	webx.Run("0.0.0.0:9999")
}
