package log

import (
	"io"
	"os"
	"path/filepath"
	"time"
)

var _ io.Writer = &Files{}

type ByType int

const (
	ByDay ByType = iota
	ByHour
	ByMonth
)

var (
	formats = map[ByType]string{
		ByDay:   "2006-01-02",
		ByHour:  "2006-01-02-15",
		ByMonth: "2006-01",
	}
)

func SetFileFormat(t ByType, format string) {
	formats[t] = format
}

func (b ByType) Format() string {
	return formats[b]
}

type Files struct {
	FileOptions
	f          *os.File
	lastFormat string
}

type FileOptions struct {
	Dir string
	ByType ByType
}

func prePareFileOption(opts []FileOptions) FileOptions {
	var opt FileOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.Dir == "" {
		opt.Dir = "./"
	}
	return opt
}

func NewFileWriter(opts ...FileOptions) *Files {
	opt := prePareFileOption(opts)
	return &Files{
		FileOptions: opt,
	}
}

func (f *Files) getFile() (*os.File, error) {
	if f.f == nil {
		f.lastFormat = time.Now().Format(f.ByType.Format())
		var err error
		f.f, err = os.Create(filepath.Join(f.Dir, f.lastFormat+".log"))
		return f.f, err
	}
	if f.lastFormat != time.Now().Format(f.ByType.Format()) {
		f.f.Close()
		f.lastFormat = time.Now().Format(f.ByType.Format())
		var err error
		f.f, err = os.Create(filepath.Join(f.Dir, f.lastFormat+".log"))
		return f.f, err
	}
	return f.f, nil
}

func (f *Files) Write(bs []byte) (int, error) {
	w, err := f.getFile()
	if err != nil {
		return 0, err
	}
	return w.Write(bs)
}

func (f *Files) Close() {
	if f.f != nil {
		f.f.Close()
		f.f = nil
	}
	f.lastFormat = ""
}
