package reflected

import (
	"reflect"
)

type Reflected struct {
	Handles []Handler
	reflect.Value
	reflect.Type
}

type Handler interface {
	Exec(...reflect.Value) []reflect.Value
	SetArgs([]reflect.Value)
}

type Handle struct {
	Method    reflect.Value
	Args      []reflect.Value
	NumIn     int
	ExtMethod map[string]reflect.Value
}

func (h *Handle) Exec(_ ...reflect.Value) []reflect.Value {
	return h.Method.Call(h.Args)
}

func (h *Handle) SetArgs(args []reflect.Value) {
	h.Args = args
}

type HandleInit struct {
	Method reflect.Value
}

func (h *HandleInit) Exec(_ ...reflect.Value) []reflect.Value {
	return h.Method.Call([]reflect.Value{})
}

func (h *HandleInit) SetArgs(_ []reflect.Value) {
}

type HandleBefore struct {
	Method reflect.Value
	Args   []reflect.Value
}

func (h *HandleBefore) Exec(_ ...reflect.Value) []reflect.Value {
	return h.Method.Call(h.Args)
}

func (h *HandleBefore) SetArgs(_ []reflect.Value) {
}

type HandleAfter struct {
	Method reflect.Value
	Args   []reflect.Value
}

func (h *HandleAfter) Exec(r ...reflect.Value) []reflect.Value {
	return h.Method.Call(append(h.Args, r...))
}

func (h *HandleAfter) SetArgs(_ []reflect.Value) {
}
