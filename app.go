package webx

import (
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coscms/tagfast"
	"github.com/coscms/webx/lib/httpsession"
	"github.com/coscms/webx/lib/log"
	"github.com/coscms/webx/lib/route"
	"github.com/coscms/webx/lib/tplex"
)

var (
	mapperType = reflect.TypeOf(Mapper{})

	//解析网址模板中的参数名。匹配: ({name}) / (a{name}b)
	urlTmplRgx = regexp.MustCompile(`\(([^}]*)\{([^}]+)\}([^}]*)\)`)
)

type Mapper struct{}

func NewTagMapper(rawUrl string) *TagMapper {
	return &TagMapper{
		RawUrl: rawUrl,
		Mapper: make(map[string][2]string), //0:匹配到的整个字串；1:网址模板"a%vb"
	}
}

type TagMapper struct {
	RawUrl string
	Mapper map[string][2]string
	Memo   string
}

func (m *TagMapper) GenUrl(vals interface{}) (r string) {
	r = m.RawUrl
	if r == "" {
		return
	}
	switch vals.(type) {
	case url.Values:
		val := vals.(url.Values)
		for name, mapper := range m.Mapper {
			r = m.Replace(r, val.Get(name), mapper)
		}
	case map[string]string:
		val := vals.(map[string]string)
		for name, mapper := range m.Mapper {
			v, _ := val[name]
			r = m.Replace(r, v, mapper)
		}
	default:
		for _, mapper := range m.Mapper {
			r = m.Replace(r, "", mapper)
		}
	}
	return
}

func (m *TagMapper) Replace(r string, v string, mapper [2]string) string {
	if v == "" {
		r = strings.Replace(r, mapper[0], v, -1)
	} else {
		r = strings.Replace(r, mapper[0], fmt.Sprintf(mapper[1], v), -1)
	}
	return r
}

type JSON struct {
	Data interface{}
}

type JSONP struct {
	Data     interface{}
	Callback string
}

type SHOW struct {
	Tmpl string
	*T
}

type JUMP struct {
	Url  string
	Code int
}

type XML struct {
	Data interface{}
}

type FILE struct {
	Data string
}

var ExtensionValidator = make(map[string]func(*App, http.ResponseWriter, *http.Request) bool)

const (
	Debug = iota + 1
	Product
	XSRF_TAG string = "_xsrf"
)

type App struct {
	BasePath        string
	Name            string
	Domain          string
	Route           *route.Route
	filters         []Filter
	Server          *Server
	AppConfig       *AppConfig
	Config          *CONF
	Actions         map[string]interface{}
	ReflectedType   map[string]reflect.Type
	Controllers     map[reflect.Type]*sync.Pool
	Urls            map[reflect.Type]map[string]*TagMapper
	FuncMaps        template.FuncMap
	Logger          *log.Logger
	VarMaps         T
	SessionManager  *httpsession.Manager //Session manager
	RootTemplate    *template.Template
	ErrorTemplate   *template.Template
	StaticVerMgr    *StaticVerMgr
	TemplateEx      *tplex.TemplateEx
	ContentEncoding string
	RequestTime     time.Time
	actionPool      *sync.Pool
	RouteValidator  func(*App, string) (string, error)
	ActionValidator func(*App, reflect.Type, reflect.Value) bool
	Cryptor
	XsrfManager
}

func NewAppConfig() *AppConfig {
	return &AppConfig{
		Mode:              Product,
		StaticDir:         "static",
		TemplateDir:       "templates",
		SessionOn:         true,
		SessionTimeout:    3600,
		MaxUploadSize:     10 * 1024 * 1024,
		StaticFileVersion: true,
		CacheTemplates:    true,
		ReloadTemplates:   true,
		CheckXsrf:         true,
		FormMapToStruct:   true,
		StaticFileParser:  make(map[string]func(string, *http.Request, http.ResponseWriter) (bool, int64)),
	}
}

type AppConfig struct {
	Mode              int
	StaticDir         string
	TemplateDir       string
	TemplateTheme     string
	TemplateStyle     string
	SessionOn         bool
	MaxUploadSize     int64
	CookieSecret      string
	CookieLimitIP     bool
	CookieLimitUA     bool
	CookiePrefix      string
	CookieDomain      string
	StaticFileVersion bool
	CacheTemplates    bool
	ReloadTemplates   bool
	CheckXsrf         bool
	SessionTimeout    time.Duration
	FormMapToStruct   bool
	EnableHttpCache   bool
	AuthBasedOnCookie bool
	StaticFileParser  map[string]func(string, *http.Request, http.ResponseWriter) (bool, int64)
	//example: StaticFileParser[php]=func(fileName string, req *http.Request, w http.ResponseWriter)(bool, int64){...}
}

func NewApp(path string, name string) *App {
	app := &App{
		BasePath:      path,
		Name:          name,
		Route:         route.NewRoute(),
		AppConfig:     NewAppConfig(),
		Config:        NewCONF(),
		Actions:       map[string]interface{}{},
		ReflectedType: map[string]reflect.Type{},
		Controllers:   map[reflect.Type]*sync.Pool{},
		Urls:          make(map[reflect.Type]map[string]*TagMapper),
		FuncMaps:      DefaultFuncs,
		VarMaps:       T{},
		filters:       make([]Filter, 0),
		StaticVerMgr:  DefaultStaticVerMgr,
		Cryptor:       DefaultCryptor,
		XsrfManager:   DefaultXsrfManager,
		actionPool:    &sync.Pool{},
	}
	(*app.actionPool).New = func() interface{} {
		return NewAction(app)
	}
	return app
}

func (a *App) IsRootApp() bool {
	return a.BasePath == "/"
}

func (a *App) initApp() {
	var isRootApp bool = a.IsRootApp()
	if a.AppConfig.StaticFileVersion {
		if isRootApp || a.Server.RootApp.AppConfig.StaticDir != a.AppConfig.StaticDir {
			if !isRootApp {
				a.StaticVerMgr = new(StaticVerMgr)
			}
			a.StaticVerMgr.Init(a, a.AppConfig.StaticDir)
		} else {
			a.StaticVerMgr = a.Server.RootApp.StaticVerMgr
		}
	}
	if isRootApp || a.Server.RootApp.AppConfig.TemplateDir != a.AppConfig.TemplateDir {
		a.TemplateEx = tplex.New(a.Logger, a.AppConfig.TemplateDir, a.AppConfig.CacheTemplates, a.AppConfig.ReloadTemplates)
		a.TemplateEx.TemplatePathParser = func(tmplPath string) string {
			if len(tmplPath) > 2 && tmplPath[1] == ':' {
				switch tmplPath[0] {
				case '#':
					tmplPath = "#shared/" + tmplPath[2:]
				case '.':
					tmplPath = a.Name + "/" + tmplPath[2:]
				case '^':
					return tmplPath[2:]
				}
			}
			if a.AppConfig.TemplateTheme != "" {
				tmplPath = a.AppConfig.TemplateTheme + "/" + tmplPath
			}
			return tmplPath
		}
	} else {
		a.TemplateEx = a.Server.RootApp.TemplateEx
	}
	a.FuncMaps["StaticUrl"] = a.StaticUrl
	a.FuncMaps["XsrfName"] = XsrfName
	a.VarMaps["webxVer"] = Version

	if a.AppConfig.SessionOn {
		if a.Server.SessionManager != nil {
			a.SessionManager = a.Server.SessionManager
		} else {
			a.SessionManager = httpsession.Default()
			if a.AppConfig.SessionTimeout > time.Second {
				a.SessionManager.SetMaxAge(a.AppConfig.SessionTimeout)
			}
			a.SessionManager.Run()
		}
	}

	if a.Logger == nil {
		a.Logger = a.Server.Logger
	}
}

func (a *App) Close() {
	if a.AppConfig.StaticFileVersion && a.StaticVerMgr != nil {
		a.StaticVerMgr.Close()
	}
	if a.AppConfig.CacheTemplates && a.TemplateEx != nil && a.TemplateEx.TemplateMgr != nil {
		a.TemplateEx.TemplateMgr.Close()
	}
	if a.AppConfig.SessionOn && a.Server.SessionManager == nil &&
		a.SessionManager != nil {
		//a.SessionManager.Close()
	}

}

func (a *App) DelDomain() {
	a.Domain = ""
	if domain, ok := a.Server.App2Domain[a.Name]; ok {
		delete(a.Server.App2Domain, a.Name)
		delete(a.Server.Domain2App, domain)
	}
}

func (a *App) SetDomain(domain string) {
	a.Domain = domain
	a.Server.App2Domain[a.Name] = domain
	a.Server.Domain2App[domain] = a.Name
}

func (a *App) SetStaticDir(dir string) {
	a.AppConfig.StaticDir = dir
}

func (a *App) SetTemplateDir(path string) {
	a.AppConfig.TemplateDir = path
}

func (a *App) getTemplatePath(name string) string {
	templateFile := path.Join(a.AppConfig.TemplateDir, name)
	if fileExists(templateFile) {
		return templateFile
	}
	return ""
}

func (app *App) SetConfig(name string, val interface{}) {
	app.Config.SetInterface(name, val)
}

func (app *App) GetConfig(name string) interface{} {
	return app.Config.GetInterface(name)
}

func (app *App) SetConfigString(name string, val string) {
	app.Config.SetString(name, val)
}

func (app *App) GetConfigString(name string) string {
	return app.Config.GetString(name)
}

func (app *App) AddAction(cs ...interface{}) {
	for _, c := range cs {
		app.AddRouter("/", c)
	}
}

func (app *App) AutoAction(cs ...interface{}) {
	for _, c := range cs {
		t := reflect.Indirect(reflect.ValueOf(c)).Type()
		if strings.HasSuffix(t.Name(), "Action") {
			app.AddRouter("/", c)
		} else {
			app.Warn("AutoAction needs a named ends with Action")
		}
	}
}

func (app *App) Assign(name string, varOrFun interface{}) {
	if reflect.TypeOf(varOrFun).Kind() == reflect.Func {
		app.FuncMaps[name] = varOrFun
	} else {
		app.VarMaps[name] = varOrFun
	}
}

func (app *App) MultiAssign(t *T) {
	for name, value := range *t {
		app.Assign(name, value)
	}
}

func (app *App) AddFilter(filter Filter) {
	app.filters = append(app.filters, filter)
}

func (app *App) Debug(params ...interface{}) {
	args := append([]interface{}{"[" + app.Name + "]"}, params...)
	app.Logger.Debug(args...)
}

func (app *App) Info(params ...interface{}) {
	args := append([]interface{}{"[" + app.Name + "]"}, params...)
	app.Logger.Info(args...)
}

func (app *App) Warn(params ...interface{}) {
	args := append([]interface{}{"[" + app.Name + "]"}, params...)
	app.Logger.Warn(args...)
}

func (app *App) Error(params ...interface{}) {
	args := append([]interface{}{"[" + app.Name + "]"}, params...)
	app.Logger.Error(args...)
}

func (app *App) Fatal(params ...interface{}) {
	args := append([]interface{}{"[" + app.Name + "]"}, params...)
	app.Logger.Fatal(args...)
}

func (app *App) Panic(params ...interface{}) {
	args := append([]interface{}{"[" + app.Name + "]"}, params...)
	app.Logger.Panic(args...)
}

func (app *App) Debugf(format string, params ...interface{}) {
	app.Logger.Debugf("["+app.Name+"] "+format, params...)
}

func (app *App) Infof(format string, params ...interface{}) {
	app.Logger.Infof("["+app.Name+"] "+format, params...)
}

func (app *App) Warnf(format string, params ...interface{}) {
	app.Logger.Warnf("["+app.Name+"] "+format, params...)
}

func (app *App) Errorf(format string, params ...interface{}) {
	app.Logger.Errorf("["+app.Name+"] "+format, params...)
}

func (app *App) Fatalf(format string, params ...interface{}) {
	app.Logger.Fatalf("["+app.Name+"] "+format, params...)
}

func (app *App) Panicf(format string, params ...interface{}) {
	app.Logger.Panicf("["+app.Name+"] "+format, params...)
}

func (app *App) filter(w http.ResponseWriter, req *http.Request) bool {
	for _, filter := range app.filters {
		if !filter.Do(w, req) {
			return false
		}
	}
	return true
}

func (app *App) AddRouter(url string, c interface{}) {
	t := reflect.TypeOf(c).Elem()
	v := reflect.ValueOf(c)
	if app.ActionValidator != nil && !app.ActionValidator(app, t, v) {
		return
	}

	actionFullName := t.Name()
	actionShortName := strings.TrimSuffix(actionFullName, "Action")
	actionShortName = strings.ToLower(actionShortName)
	app.ReflectedType[actionFullName] = t
	app.Actions[actionFullName] = c
	app.Urls[t] = make(map[string]*TagMapper)
	url = strings.TrimRight(url, "/")

	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Type != mapperType {
			continue
		}
		name := t.Field(i).Name
		a := strings.Title(name)
		m := v.MethodByName(a)
		if !m.IsValid() {
			continue
		}

		//支持的tag:
		// 1. webx - 路由规则
		// 2. tmpl - 网址生成模板，带参数名称。
		//    括号部分会被完整替换，用花括号括起来的部分为参数名，它会被替换为该参数的值
		// 3. memo - 注释说明
		//`webx:"list_(\\d+)(?:_(\\d+))?" tmpl:"list_({cid})(_{page})" memo:"列表页"`
		//`webx:"index(?:_(\\d+)){0,2}" tmpl:"index(_{id})(_{page})" memo:"首页"`
		tagMapper := NewTagMapper("")
		tag := t.Field(i).Tag
		tagMapper.Memo = tag.Get("memo")
		tagMapper.RawUrl = tag.Get("tmpl")
		tagStr := tag.Get("webx")
		methods := map[string]bool{}    //map[string]bool{"GET": true, "POST": true}
		extensions := map[string]bool{} //map[string]bool{"HTML": true, "JSON": true}
		group := map[string]bool{}      //map[string]bool{"GET_HTML": true, "POST_JSON": true}
		var p, meStr string
		if tagStr != "" {
			tags := strings.Split(tagStr, " ")
			path := tagStr
			length := len(tags)
			if length >= 2 { //`webx:"GET|POST /index"`
				meStr = tags[0]
				path = tags[1]
				if path == "" {
					path = name
				}
				if tags[1][0] != '/' {
					path = "/" + actionShortName + "/" + path
				}
			} else if length == 1 {
				if matched, _ := regexp.MatchString(`^[A-Z.]+(\|[A-Z]+)*$`, tags[0]); !matched {
					//非全大写字母时，判断为网址规则
					path = tags[0]
					if tags[0][0] != '/' { //`webx:"index"`
						path = "/" + actionShortName + "/" + path
					}
				} else { //`webx:"GET|POST"`
					meStr = tags[0]
					path = "/" + actionShortName + "/" + name
				}
			} else {
				path = "/" + actionShortName + "/" + name
			}
			p = url + path
		} else {
			p = url + "/" + actionShortName + "/" + name
		}

		if tagMapper.RawUrl != "" {
			if tagMapper.RawUrl[0] != '/' {
				tagMapper.RawUrl = "/" + actionShortName + "/" + tagMapper.RawUrl
			}
			tagMapper.RawUrl = url + tagMapper.RawUrl
			sr := urlTmplRgx.FindAllStringSubmatch(tagMapper.RawUrl, -1)
			for _, rr := range sr {
				matched := rr[0]
				prefix := rr[1]
				varname := rr[2]
				suffix := rr[3]
				tagMapper.Mapper[varname] = [2]string{matched, prefix + `%v` + suffix}
			}
		}

		methodsStr := ""
		extensionsStr := ""
		if meStr != "" {
			me := strings.Split(meStr, ".")
			methodsStr = me[0]
			if len(me) > 1 {
				extensionsStr = me[1]
			}
		}
		if methodsStr != "" {
			for _, method := range strings.Split(methodsStr, "|") {
				method = strings.ToUpper(method)
				m := v.MethodByName(a + "_" + method)
				methods[method] = m.IsValid()
			}
		} else {
			m := v.MethodByName(a + "_GET")
			methods["GET"] = m.IsValid()
			m = v.MethodByName(a + "_POST")
			methods["POST"] = m.IsValid()
		}
		if extensionsStr != "" {
			for _, extension := range strings.Split(extensionsStr, "|") {
				extension = strings.ToUpper(extension)
				m := v.MethodByName(a + "_" + extension)
				extensions[extension] = m.IsValid()
			}
		}
		if len(methods) > 0 && len(extensions) > 0 {
			for method, _ := range methods {
				for extension, _ := range extensions {
					key := method + "_" + extension
					m := v.MethodByName(a + "_" + key)
					group[key] = m.IsValid()
				}
			}
		}

		if app.RouteValidator != nil {
			if path, err := app.RouteValidator(app, p); err == nil {
				p = path
			} else {
				continue
			}
		}
		app.Urls[t][name] = tagMapper
		app.Route.Set(p, a, methods, extensions, group, t)
		app.Debug("Action:", actionFullName+"."+a+";", "Route Information:", p+";", "Request Method:", methods)
	}
}

func (a *App) ElapsedTimeString() string {
	return fmt.Sprintf("%.3fs", a.ElapsedTime())
}

func (a *App) ElapsedTime() float64 {
	return time.Now().Sub(a.RequestTime).Seconds()
}

func (a *App) VisitedLog(req *http.Request, statusCode int, requestPath string, responseSize int64) {
	if statusCode == 0 {
		statusCode = 200
	}
	if statusCode >= 200 && statusCode < 400 {
		a.Info(req.RemoteAddr, req.Method, statusCode, requestPath, responseSize, a.ElapsedTimeString())
	} else {
		a.Error(req.RemoteAddr, req.Method, statusCode, requestPath, responseSize, a.ElapsedTimeString())
	}
}

// the main route handler in web.go
func (a *App) routeHandler(req *http.Request, w http.ResponseWriter) {
	var (
		requestPath  string = req.URL.Path
		statusCode   int    = 0
		responseSize int64  = 0
	)
	defer func() {
		a.VisitedLog(req, statusCode, requestPath, responseSize)
	}()

	if !a.IsRootApp() || a.Server.Config.UrlSuffix != "" || a.Server.Config.UrlPrefix != "" {
		// static files, needed op
		if req.Method == "GET" || req.Method == "HEAD" {
			success, size := a.TryServingFile(requestPath, req, w)
			if success {
				statusCode = 200
				responseSize = size
				return
			}
			if requestPath == "/favicon.ico" {
				statusCode = 404
				a.error(w, 404, "Page not found")
				return
			}
		}
	}

	//ignore errors from ParseForm because it's usually harmless.
	ct := req.Header.Get("Content-Type")
	if strings.Contains(ct, "multipart/form-data") {
		req.ParseMultipartForm(a.AppConfig.MaxUploadSize)
		if len(req.PostForm) == 0 {
			req.PostForm = req.MultipartForm.Value
		}
	} else {
		req.ParseForm()
	}

	//Set the default content-type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !a.filter(w, req) {
		statusCode = 302
		return
	}
	extension := "html"
	reqExtension := "HTML"
	if epos := strings.LastIndex(req.URL.Path, "."); epos > 0 && epos+1 < len(req.URL.Path) {
		extension = req.URL.Path[epos+1:]
		req.URL.Path = req.URL.Path[0:epos]
		reqExtension = strings.ToUpper(extension)
	}
	if fn, ok := ExtensionValidator[extension]; ok {
		if !fn(a, w, req) {
			return
		}
	}

	requestPath = req.URL.Path //支持filter更改req.URL.Path

	reqPath := removeStick(requestPath)
	if a.Domain == "" && a.BasePath != "/" {
		reqPath = "/" + strings.TrimPrefix(reqPath, a.BasePath)
	}
	reqMethod := Ternary(req.Method == "HEAD", "GET", req.Method).(string)
	args, fnName, rfType, onMethod, onExtension, onGroup := a.Route.Get(reqPath, reqMethod, reqExtension)
	if rfType != nil && fnName != "" {
		var (
			isBreak bool
			suffix  string
		)
		if onGroup {
			suffix = "_" + reqMethod + "_" + reqExtension
		} else if onMethod {
			suffix = "_" + reqMethod
		} else if onExtension {
			suffix = "_" + reqExtension
		}
		isBreak, statusCode, responseSize = a.run(req, w, fnName, rfType, args, suffix, extension)
		if isBreak {
			return
		}
	}
	// try serving index.html or index.htm
	if req.Method == "GET" || req.Method == "HEAD" {
		if ok, size := a.TryServingFile(path.Join(requestPath, "index.html"), req, w); ok {
			statusCode = 200
			responseSize = size
			return
		} else if ok, size := a.TryServingFile(path.Join(requestPath, "index.htm"), req, w); ok {
			statusCode = 200
			responseSize = size
			return
		}
	}

	a.error(w, 404, "Page not found")
	statusCode = 404
}

type Reflected struct {
	NameV           reflect.Value
	StructV         reflect.Value
	HasFieldAction  bool
	HasMethodInit   bool
	HasMethodBefore bool
	HasMethodAfter  bool
	FieldAction     reflect.Value
	MethodInit      reflect.Value
	MethodBefore    reflect.Value
	MethodAfter     reflect.Value
	MethodByPath    map[string]reflect.Value
}

func (a *App) run(req *http.Request, w http.ResponseWriter,
	handlerName string, reflectType reflect.Type,
	args []reflect.Value, handlerSuffix string, extensionName string) (isBreak bool,
	statusCode int, responseSize int64) {

	if handlerSuffix != "" {
		handlerName += handlerSuffix
	}
	isBreak = true

	/*/==================================
	c := NewAction(a)
	c.reset(req,w,extensionName,args)

	for k, v := range args {
		c.args[k] = v.String()
	}

	for k, v := range a.VarMaps {
		c.T[k] = v
	}

	vc := reflect.New(reflectType)
	el := vc.Elem()
	if m := el.FieldByName("Action"); m.IsValid() {
		m.Set(reflect.ValueOf(c))
		//设置C字段的值
		el.FieldByName("C").Set(reflect.ValueOf(vc))
	}
	if m := vc.MethodByName("Init"); m.IsValid() {
		m.Call([]reflect.Value{})
	}
	if c.Exit {
		responseSize = c.ResponseSize
		return
	}
	//表单数据自动映射到结构体
	if c.Option.AutoMapForm {
		a.StructMap(vc.Interface(), req)
	}

	//验证XSRF
	if c.Option.CheckXsrf {
		a.XsrfManager.Init(c)
		if req.Method == "POST" {
			formVals := req.Form[XSRF_TAG]
			var formVal string
			if len(formVals) > 0 {
				formVal = formVals[0]
			}
			if formVal == "" ||
				!a.XsrfManager.Valid(a.AppConfig.CookiePrefix+
					XSRF_TAG, formVal) {
				a.error(w, 500, "xsrf token error.")
				a.Error("xsrf token error.")
				statusCode = 500
				return
			}
		}
	}
	structName := reflect.ValueOf(reflectType.Name())
	actionName := reflect.ValueOf(handlerName)

	if m := vc.MethodByName("Before"); m.IsValid() {
		structAction := []reflect.Value{structName, actionName}
		if ok := m.Call(structAction); c.Exit || (len(ok) > 0 && ok[0].Kind() == reflect.Bool && !ok[0].Bool()) {
			responseSize = c.ResponseSize
			return
		}
	}
	m := vc.MethodByName(handlerName)
	ret, err := a.SafelyCall(m, args)
	if err != nil {
		//there was an error or panic while calling the handler
		if a.AppConfig.Mode == Debug {
			a.error(w, 500, fmt.Sprintf("<pre>handler error: %v</pre>", err))
		} else if a.AppConfig.Mode == Product {
			a.error(w, 500, "Server Error")
		}
		statusCode = 500
		responseSize = c.ResponseSize
		return
	}
	statusCode = c.StatusCode

	if m := vc.MethodByName("After"); m.IsValid() {
		structAction := []reflect.Value{structName, actionName}
		structAction = append(structAction, ret...)
		if len(structAction) != m.Type().NumIn() {
			a.Errorf("Error : %v.After(): The number of params is not adapted.", structName)
			return
		}
		ret = m.Call(structAction)
	}
	//*/

	//=====================================
	pool, ok := a.Controllers[reflectType]
	if !ok {
		pool = &sync.Pool{}
		(*pool).New = func() interface{} {
			//fmt.Println("initialize Reflected pool:", reflectType.Name())
			ref := &Reflected{
				NameV:        reflect.ValueOf(reflectType.Name()),
				StructV:      reflect.New(reflectType),
				MethodByPath: make(map[string]reflect.Value),
			}
			elem := ref.StructV.Elem()
			if m := elem.FieldByName("Action"); m.IsValid() {
				ref.HasFieldAction = true
				ref.FieldAction = m
			}
			if m := ref.StructV.MethodByName("Init"); m.IsValid() {
				ref.HasMethodInit = true
				ref.MethodInit = m
			}
			if m := ref.StructV.MethodByName("Before"); m.IsValid() {
				ref.HasMethodBefore = true
				ref.MethodBefore = m
			}
			if m := ref.StructV.MethodByName("After"); m.IsValid() {
				ref.HasMethodAfter = true
				ref.MethodAfter = m
			}
			if m := ref.StructV.MethodByName(handlerName); m.IsValid() {
				ref.MethodByPath[handlerName] = m
			}
			return ref
		}

		a.Controllers[reflectType] = pool
	}

	ref := (*pool).Get().(*Reflected)
	defer (*pool).Put(ref)

	c := (*a.actionPool).Get().(*Action)
	c.reset(req, w, extensionName, args)
	defer (*a.actionPool).Put(c)

	for k, v := range args {
		c.args[k] = v.String()
	}

	for k, v := range a.VarMaps {
		c.T[k] = v
	}

	vc := ref.StructV

	//设置Action字段的值
	if ref.HasFieldAction {
		ref.FieldAction.Set(reflect.ValueOf(c))
		//设置C字段的值
		vc.Elem().FieldByName("C").Set(reflect.ValueOf(vc))
	}

	//执行Init方法
	if ref.HasMethodInit {
		ref.MethodInit.Call([]reflect.Value{})
	}

	if c.Exit {
		responseSize = c.ResponseSize
		return
	}

	//表单数据自动映射到结构体
	if c.Option.AutoMapForm {
		a.StructMap(vc.Interface(), req)
	}

	//验证XSRF
	if c.Option.CheckXsrf {
		a.XsrfManager.Init(c)
		if req.Method == "POST" {
			formVals := req.Form[XSRF_TAG]
			var formVal string
			if len(formVals) > 0 {
				formVal = formVals[0]
			}
			if formVal == "" ||
				!a.XsrfManager.Valid(a.AppConfig.CookiePrefix+
					XSRF_TAG, formVal) {
				a.error(w, 500, "xsrf token error.")
				a.Error("xsrf token error.")
				statusCode = 500
				return
			}
		}
	}
	structName := ref.NameV
	actionName := reflect.ValueOf(handlerName)

	//执行Before方法
	if ref.HasMethodBefore {
		structAction := []reflect.Value{structName, actionName}
		if ok := ref.MethodBefore.Call(structAction); c.Exit || (len(ok) > 0 && ok[0].Kind() == reflect.Bool && !ok[0].Bool()) {
			responseSize = c.ResponseSize
			return
		}
	}
	fn, ok := ref.MethodByPath[handlerName]
	if !ok {
		fn = ref.StructV.MethodByName(handlerName)
		ref.MethodByPath[handlerName] = fn
	}
	ret, err := a.SafelyCall(fn, args)
	if err != nil {
		//there was an error or panic while calling the handler
		if a.AppConfig.Mode == Debug {
			a.error(w, 500, fmt.Sprintf("<pre>handler error: %v</pre>", err))
		} else if a.AppConfig.Mode == Product {
			a.error(w, 500, "Server Error")
		}
		statusCode = 500
		responseSize = c.ResponseSize
		return
	}
	statusCode = c.StatusCode

	//执行After方法
	if ref.HasMethodAfter {
		structAction := []reflect.Value{structName, actionName}
		structAction = append(structAction, ret...)
		if len(structAction) != ref.MethodAfter.Type().NumIn() {
			a.Errorf("Error : %v.After(): The number of params is not adapted.", structName)
			return
		}
		ret = ref.MethodAfter.Call(structAction)
	}
	// */
	if c.Exit {
		responseSize = c.ResponseSize
		return
	}
	if len(ret) == 0 {
		defaultResponse(c, nil)
		responseSize = c.ResponseSize
		return
	}

	sval := ret[0]
	intf := sval.Interface()

	if intf == nil {
		responseSize = c.ResponseSize
		return
	}

	kind := sval.Kind()
	var content []byte
	switch kind {
	case reflect.Bool:
		responseSize = c.ResponseSize
		return
	case reflect.String:
		content = []byte(sval.String())
	case reflect.Slice:
		if sval.Type().Elem().Kind() == reflect.Uint8 {
			content = intf.([]byte)
			break
		}
		fallthrough
	default:
		switch intf.(type) {
		case bool:
			responseSize = c.ResponseSize
			return
		case JSON:
			obj, _ := intf.(JSON)
			c.ServeJson(obj.Data)
			responseSize = c.ResponseSize
			return
		case JSONP:
			obj, _ := intf.(JSONP)
			c.ServeJsonp(obj.Data, obj.Callback)
			responseSize = c.ResponseSize
			return
		case XML:
			obj, _ := intf.(XML)
			c.ServeXml(obj.Data)
			responseSize = c.ResponseSize
			return
		case FILE:
			obj, _ := intf.(FILE)
			c.ServeFile(obj.Data)
			return
		case SHOW:
			obj, _ := intf.(SHOW)
			c.Render(obj.Tmpl, obj.T)
			return
		case JUMP:
			obj, _ := intf.(JUMP)
			c.Redirect(obj.Url, obj.Code)
			return
		case error:
			err, _ := intf.(error)
			if err != nil {
				a.Error("Error:", err)
				a.error(w, 500, "Server Error")
				statusCode = 500
			} else {
				responseSize = c.ResponseSize
			}
			return
		case string:
			str, _ := intf.(string)
			content = []byte(str)
		case []byte:
			content, _ = intf.([]byte)
		default:
			var validType bool
			Event("webx:outputBaseonExtension", []interface{}{c, intf}, func(ok bool) {
				if !ok {
					validType = true
					return
				}
				responseSize, validType = defaultResponse(c, intf)
			})
			if !validType {
				a.Warnf("unknown returned result type %v, ignored %v", kind, intf)
			}
			return
		}
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	size, err := w.Write(content)
	if err != nil {
		a.Errorf("Error during write: %v", err)
		statusCode = 500
	} else {
		responseSize = int64(size)
	}
	return
}

func defaultResponse(c *Action, data interface{}) (responseSize int64, validType bool) {
	switch c.ExtensionName {
	case "json":
		if data == nil {
			data = JSONResponse{Status: 1, Message: "", Data: c.T}
		}
		c.ServeJson(data)
		responseSize = c.ResponseSize
		validType = true
	case "xml":
		if data == nil {
			data = XMLResponse{Status: 1, Message: "", Data: c.T}
		}
		c.ServeXml(data)
		responseSize = c.ResponseSize
		validType = true
	}
	return
}

func (a *App) error(w http.ResponseWriter, status int, content string) error {
	w.WriteHeader(status)
	if errorTmpl == "" {
		errTmplFile := a.AppConfig.TemplateDir + "/_error.html"
		if file, err := os.Stat(errTmplFile); err == nil && !file.IsDir() {
			if b, e := ioutil.ReadFile(errTmplFile); e == nil {
				errorTmpl = string(b)
			}
		}
		if errorTmpl == "" {
			errorTmpl = defaultErrorTmpl
		}
	}
	res := fmt.Sprintf(errorTmpl, status, statusText[status],
		status, statusText[status], content, Version)
	_, err := w.Write([]byte(res))
	return err
}

func (a *App) StaticUrl(url string) string {
	var basePath string
	if a.AppConfig.StaticDir == RootApp().AppConfig.StaticDir {
		basePath = RootApp().BasePath
	} else {
		basePath = a.BasePath
	}
	if !a.AppConfig.StaticFileVersion {
		return path.Join(basePath, url)
	}
	ver := a.StaticVerMgr.GetVersion(url)
	if ver == "" {
		return path.Join(basePath, url)
	}
	return path.Join(basePath, url+"?v="+ver)
}

// safelyCall invokes `function` in recover block
func (a *App) SafelyCall(fn reflect.Value, args []reflect.Value) (resp []reflect.Value, err error) {
	defer func() {
		if e := recover(); e != nil {
			if !a.Server.Config.RecoverPanic {
				// go back to panic
				panic(e)
			} else {
				resp = nil
				var content string
				content = fmt.Sprintf("Handler crashed with error: %v", e)
				for i := 1; ; i += 1 {
					_, file, line, ok := runtime.Caller(i)
					if !ok {
						break
					} else {
						content += "\n"
					}
					content += fmt.Sprintf("%v %v", file, line)
				}
				a.Error(content)
				err = errors.New(content)
				return
			}
		}
	}()
	if fn.Type().NumIn() > 0 {
		return fn.Call(args), err
	}
	return fn.Call(nil), err
}

// Init content-length header.
func (a *App) InitHeadContent(w http.ResponseWriter, contentLength int64) {
	if a.ContentEncoding == "gzip" {
		w.Header().Set("Content-Encoding", "gzip")
	} else if a.ContentEncoding == "deflate" {
		w.Header().Set("Content-Encoding", "deflate")
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	}
}

// tryServingFile attempts to serve a static file, and returns
// whether or not the operation is successful.
func (a *App) TryServingFile(name string, req *http.Request, w http.ResponseWriter) (bool, int64) {
	newPath := name
	if strings.HasPrefix(name, a.BasePath) {
		newPath = name[len(a.BasePath):]
	}
	var size int64
	staticFile := filepath.Join(a.AppConfig.StaticDir, newPath)
	finfo, err := os.Stat(staticFile)
	if err != nil {
		return false, size
	}
	if finfo.IsDir() {
		return false, size
	}
	if a.AppConfig.StaticFileParser != nil {
		extName := filepath.Ext(staticFile)
		if len(extName) > 0 {
			if fn, ok := a.AppConfig.StaticFileParser[strings.ToLower(extName[1:])]; ok {
				return fn(staticFile, req, w)
			}
		}
	}
	size = finfo.Size()
	isStaticFileToCompress := false
	if a.Server.Config.EnableGzip && a.Server.Config.StaticExtensionsToGzip != nil && len(a.Server.Config.StaticExtensionsToGzip) > 0 {
		for _, statExtension := range a.Server.Config.StaticExtensionsToGzip {
			if strings.HasSuffix(strings.ToLower(staticFile), strings.ToLower(statExtension)) {
				isStaticFileToCompress = true
				break
			}
		}
	}
	if isStaticFileToCompress {
		a.ContentEncoding = GetAcceptEncodingZip(req)
		memzipfile, err := OpenMemZipFile(staticFile, a.ContentEncoding)
		if err != nil {
			return false, size
		}
		a.InitHeadContent(w, finfo.Size())
		http.ServeContent(w, req, staticFile, finfo.ModTime(), memzipfile)
	} else {
		http.ServeFile(w, req, staticFile)
	}
	return true, size
}

// StructMap function mapping params to controller's properties
func (a *App) StructMap(m interface{}, r *http.Request) error {
	return a.namedStructMap(m, r, "")
}

// user[name][test]
func SplitJson(s string) ([]string, error) {
	res := make([]string, 0)
	var begin, end int
	var isleft bool
	for i, r := range s {
		switch r {
		case '[':
			isleft = true
			if i > 0 && s[i-1] != ']' {
				if begin == end {
					return nil, errors.New("unknow character")
				}
				res = append(res, s[begin:end+1])
			}
			begin = i + 1
			end = begin
		case ']':
			if !isleft {
				return nil, errors.New("unknow character")
			}
			isleft = false
			if begin != end {
				//return nil, errors.New("unknow character")

				res = append(res, s[begin:end+1])
				begin = i + 1
				end = begin
			}
		default:
			end = i
		}
		if i == len(s)-1 && begin != end {
			res = append(res, s[begin:end+1])
		}
	}
	return res, nil
}

func (a *App) namedStructMap(m interface{}, r *http.Request, topName string) error {

	vc := reflect.ValueOf(m)
	tc := reflect.TypeOf(m)

	switch tc.Kind() {
	case reflect.Struct:
	case reflect.Ptr:
		vc = vc.Elem()
		tc = tc.Elem()
	}

	for k, t := range r.Form {

		if k == XSRF_TAG || k == "" {
			continue
		}

		if topName != "" {
			if !strings.HasPrefix(k, topName) {
				continue
			}
			k = k[len(topName)+1:]
		}

		v := t[0]
		names := strings.Split(k, ".")
		var err error
		length := len(names)
		if length == 1 {
			names, err = SplitJson(k)
			if err != nil {
				a.Warn("Unrecognize form key", k, err)
				continue
			}
		}
		length = len(names)
		var value reflect.Value = vc
		for i, name := range names {
			name = strings.Title(name)

			//不是最后一个元素
			if i != length-1 {
				if value.Kind() != reflect.Struct {
					a.Warnf("arg error, value kind is %v", value.Kind())
					break
				}

				value = value.FieldByName(name)
				if !value.IsValid() {
					a.Warnf("(%v value is not valid %v)", name, value)
					break
				}
				if !value.CanSet() {
					a.Warnf("can not set %v -> %v", name, value.Interface())
					break
				}
				if tagfast.Tag2(tc, name, "form_options") == "-" {
					continue
				}
				if value.Kind() == reflect.Ptr {
					if value.IsNil() {
						value.Set(reflect.New(value.Type().Elem()))
					}
					value = value.Elem()
				}
			} else {
				if value.Kind() != reflect.Struct {
					a.Warnf("arg error, value %v kind is %v", name, value.Kind())
					break
				}
				tv := value.FieldByName(name)
				if !tv.IsValid() {
					break
				}
				if !tv.CanSet() {
					a.Warnf("can not set %v to %v", k, tv)
					break
				}
				if tagfast.Tag2(tc, name, "form_options") == "-" {
					continue
				}
				if tv.Kind() == reflect.Ptr {
					tv.Set(reflect.New(tv.Type().Elem()))
					tv = tv.Elem()
				}

				var l interface{}
				switch k := tv.Kind(); k {
				case reflect.String:
					switch tagfast.Tag2(tc, name, "form_filter") {
					case "html":
						v = DefaultHtmlFilter(v)
					}
					l = v
					tv.Set(reflect.ValueOf(l))
				case reflect.Bool:
					l = (v != "false" && v != "0")
					tv.Set(reflect.ValueOf(l))
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
					x, err := strconv.Atoi(v)
					if err != nil {
						a.Warnf("arg %v as int: %v", v, err)
						break
					}
					l = x
					tv.Set(reflect.ValueOf(l))
				case reflect.Int64:
					x, err := strconv.ParseInt(v, 10, 64)
					if err != nil {
						a.Warnf("arg %v as int64: %v", v, err)
						break
					}
					l = x
					tv.Set(reflect.ValueOf(l))
				case reflect.Float32, reflect.Float64:
					x, err := strconv.ParseFloat(v, 64)
					if err != nil {
						a.Warnf("arg %v as float64: %v", v, err)
						break
					}
					l = x
					tv.Set(reflect.ValueOf(l))
				case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
					x, err := strconv.ParseUint(v, 10, 64)
					if err != nil {
						a.Warnf("arg %v as uint: %v", v, err)
						break
					}
					l = x
					tv.Set(reflect.ValueOf(l))
				case reflect.Struct:
					if tvf, ok := tv.Interface().(FromConversion); ok {
						err := tvf.FromString(v)
						if err != nil {
							a.Warnf("struct %v invoke FromString faild", tvf)
						}
					} else if tv.Type().String() == "time.Time" {
						x, err := time.Parse("2006-01-02 15:04:05.000 -0700", v)
						if err != nil {
							x, err = time.Parse("2006-01-02 15:04:05", v)
							if err != nil {
								x, err = time.Parse("2006-01-02", v)
								if err != nil {
									a.Warnf("unsupported time format %v, %v", v, err)
									break
								}
							}
						}
						l = x
						tv.Set(reflect.ValueOf(l))
					} else {
						a.Warn("can not set an struct which is not implement Fromconversion interface")
					}
				case reflect.Ptr:
					a.Warn("can not set an ptr of ptr")
				case reflect.Slice, reflect.Array:
					tt := tv.Type().Elem()
					tk := tt.Kind()

					if tv.IsNil() {
						tv.Set(reflect.MakeSlice(tv.Type(), len(t), len(t)))
					}

					for i, s := range t {
						var err error
						switch tk {
						case reflect.Int, reflect.Int16, reflect.Int32, reflect.Int8, reflect.Int64:
							var v int64
							v, err = strconv.ParseInt(s, 10, tt.Bits())
							if err == nil {
								tv.Index(i).SetInt(v)
							}
						case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
							var v uint64
							v, err = strconv.ParseUint(s, 10, tt.Bits())
							if err == nil {
								tv.Index(i).SetUint(v)
							}
						case reflect.Float32, reflect.Float64:
							var v float64
							v, err = strconv.ParseFloat(s, tt.Bits())
							if err == nil {
								tv.Index(i).SetFloat(v)
							}
						case reflect.Bool:
							var v bool
							v, err = strconv.ParseBool(s)
							if err == nil {
								tv.Index(i).SetBool(v)
							}
						case reflect.String:
							tv.Index(i).SetString(s)
						case reflect.Complex64, reflect.Complex128:
							// TODO:
							err = fmt.Errorf("unsupported slice element type %v", tk.String())
						default:
							err = fmt.Errorf("unsupported slice element type %v", tk.String())
						}
						if err != nil {
							a.Warnf("slice error: %v, %v", name, err)
							break
						}
					}
				default:
					break
				}
			}
		}
	}
	return nil
}

func (app *App) Redirect(w http.ResponseWriter, requestPath, url string, status ...int) error {
	err := redirect(w, url, status...)
	if err != nil {
		app.Errorf("redirect error: %s", err)
		return err
	}
	return nil
}

func (app *App) Action(name string) interface{} {
	if v, ok := app.Actions[name]; ok {
		return v
	}
	return nil
}

/*
example:
{
	"AdminAction":{
		"Index":["GET","POST"],
		"Add":	["GET","POST"],
		"Edit":	["GET","POST"]
	}
}
*/
func (app *App) Nodes() (r map[string]map[string][]string) {
	r = make(map[string]map[string][]string)
	for _, val := range app.Route.Regexp {
		name := val.ReflectType.Name()
		if _, ok := r[name]; !ok {
			r[name] = make(map[string][]string)
		}
		if _, ok := r[name][val.ExecuteFunc]; !ok {
			r[name][val.ExecuteFunc] = make([]string, 0)
		}
		for k, _ := range val.RequestMethod {
			r[name][val.ExecuteFunc] = append(r[name][val.ExecuteFunc], k) //FUNC1:[POST,GET]
		}
	}
	for _, val := range app.Route.Static {
		name := val.ReflectType.Name()
		if _, ok := r[name]; !ok {
			r[name] = make(map[string][]string)
		}
		if _, ok := r[name][val.ExecuteFunc]; !ok {
			r[name][val.ExecuteFunc] = make([]string, 0)
		}
		for k, _ := range val.RequestMethod {
			r[name][val.ExecuteFunc] = append(r[name][val.ExecuteFunc], k) //FUNC1:[POST,GET]
		}
	}
	return
}
