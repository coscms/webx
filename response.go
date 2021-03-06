package webx

import (
	"reflect"
	"strconv"
)

/*func (r http.ResponseWriter) Abort(status int, body ...string) error {
	r.WriteHeader(status)
	_, err := r.Write([]byte(body))
	return err
}*/

type Response interface {
	Do(ret []reflect.Value)
}

var (
	responses map[string]Response = make(map[string]Response)
)

type AutoResponse struct {
}

func (s *AutoResponse) Do(c *Action, ret []reflect.Value) error {
	sval := ret[0]

	var content []byte
	if sval.Kind() == reflect.String {
		content = []byte(sval.String())
	} else if sval.Kind() == reflect.Slice && sval.Type().Elem().Kind() == reflect.Uint8 {
		content = sval.Interface().([]byte)
	} else if e, ok := sval.Interface().(error); ok && e != nil {
		c.GetLogger().Println(e)
		return Abort(500, "Server Error")
	}
	c.SetHeader("Content-Length", strconv.Itoa(len(content)))
	size, err := c.ResponseWriter.Write(content)
	c.ResponseSize += int64(size)
	return err
}

type JSONResponse struct {
	Status  int
	Message interface{}
	Data    interface{}
}

func (j *JSONResponse) Do(c *Action, ret []reflect.Value) error {
	//return c.ServeJson(obj)
	return nil
}

type XMLResponse struct {
	Status  int
	Message interface{}
	Data    interface{}
}

func (x *XMLResponse) Do(c *Action, ret []reflect.Value) error {
	return nil
}
