/**
 * 模板扩展
 * @author swh <swh@admpub.com>
 */
package tplex

import (
	"bytes"
	"fmt"
	htmlTpl "html/template"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/coscms/webx/lib/log"
)

func New(logger *log.Logger, templateDir string, cached ...bool) *TemplateEx {
	t := &TemplateEx{
		CachedRelation: make(map[string]*CcRel),
		TemplateDir:    templateDir,
		TemplateMgr:    new(TemplateMgr),
		DelimLeft:      "{{",
		DelimRight:     "}}",
		IncludeTag:     "Include",
		ExtendTag:      "Extend",
		BlockTag:       "Block",
		Ext:            ".html",
	}
	mgrCtlLen := len(cached)
	if mgrCtlLen > 0 && cached[0] {
		reloadTemplates := true
		if mgrCtlLen > 1 {
			reloadTemplates = cached[1]
		}
		t.TemplateMgr.OnChangeCallback = func(name, typ, event string) {
			switch event {
			case "create":
			case "delete", "modify", "rename":
				if typ == "dir" {
					return
				}
				if cs, ok := t.CachedRelation[name]; ok {
					for key, _ := range cs.Rel {
						if name == key {
							logger.Infof("remove cached template object: %v", key)
							continue
						}
						if _, ok := t.CachedRelation[key]; ok {
							logger.Infof("remove cached template object: %v", key)
							delete(t.CachedRelation, key)
						}
					}
					delete(t.CachedRelation, name)
				}
			}
		}
		t.TemplateMgr.Init(logger, templateDir, reloadTemplates)
	}
	return t
}

type CcRel struct {
	Rel map[string]uint8
	Tpl [2]*htmlTpl.Template //0是独立模板；1是子模板
}

type TemplateEx struct {
	CachedRelation     map[string]*CcRel
	TemplateDir        string
	TemplateMgr        *TemplateMgr
	BeforeRender       func(*string)
	DelimLeft          string
	DelimRight         string
	incTagRegex        *regexp.Regexp
	extTagRegex        *regexp.Regexp
	blkTagRegex        *regexp.Regexp
	cachedRegexIdent   string
	IncludeTag         string
	ExtendTag          string
	BlockTag           string
	Ext                string
	TemplatePathParser func(string) string
}

func (self *TemplateEx) TemplatePath(p string) string {
	if self.TemplatePathParser == nil {
		return p
	}
	return self.TemplatePathParser(p)
}

func (self *TemplateEx) Fetch(tmplName string, fn func() htmlTpl.FuncMap, values interface{}) string {
	tmplName += self.Ext
	var tmpl *htmlTpl.Template
	var funcMap htmlTpl.FuncMap
	if fn != nil {
		funcMap = fn()
	}
	tmplName = self.TemplatePath(tmplName)
	cv, ok := self.CachedRelation[tmplName]
	if !ok || cv.Tpl[0] == nil {
		b, err := self.RawContent(tmplName)
		if err != nil {
			return fmt.Sprintf("RenderTemplate %v read err: %s", tmplName, err)
		}

		content := string(b)
		if self.BeforeRender != nil {
			self.BeforeRender(&content)
		}
		subcs := make(map[string]string, 0) //子模板内容
		extcs := make(map[string]string, 0) //母板内容

		ident := self.DelimLeft + self.IncludeTag + self.DelimRight
		if self.cachedRegexIdent != ident || self.incTagRegex == nil {
			left := regexp.QuoteMeta(self.DelimLeft)
			right := regexp.QuoteMeta(self.DelimRight)
			rfirst := regexp.QuoteMeta(self.DelimRight[0:1])
			self.incTagRegex = regexp.MustCompile(left + self.IncludeTag + `[\s]+"([^"]+)"(?:[\s]+([^` + rfirst + `]+))?[\s]*` + right)
			self.extTagRegex = regexp.MustCompile(left + self.ExtendTag + `[\s]+"([^"]+)"(?:[\s]+([^` + rfirst + `]+))?[\s]*` + right)
			self.blkTagRegex = regexp.MustCompile(`(?s)` + left + self.BlockTag + `[\s]+"([^"]+)"[\s]*` + right + `(.*?)` + left + `\/` + self.BlockTag + right)
		}
		m := self.extTagRegex.FindAllStringSubmatch(content, 1)
		if len(m) > 0 {
			self.ParseBlock(content, &subcs, &extcs)
			extFile := m[0][1] + self.Ext
			passObject := m[0][2]
			extFile = self.TemplatePath(extFile)
			b, err = self.RawContent(extFile)
			if err != nil {
				return fmt.Sprintf("RenderTemplate %v read err: %s", extFile, err)
			}
			content = string(b)
			content = self.ParseExtend(content, &extcs, passObject)
		}
		content = self.ContainsSubTpl(content, &subcs)
		t := htmlTpl.New(tmplName)
		t.Delims(self.DelimLeft, self.DelimRight)
		t.Funcs(funcMap)

		tmpl, err = t.Parse(content)
		if err != nil {
			return fmt.Sprintf("Parse %v err: %v", tmplName, err)
		}
		for name, subc := range subcs {
			v, ok := self.CachedRelation[name]
			if ok && v.Tpl[1] != nil {
				self.CachedRelation[name].Rel[tmplName] = 0
				continue
			}
			var t *htmlTpl.Template
			if name == tmpl.Name() {
				t = tmpl
			} else {
				t = tmpl.New(name)
			}
			if self.BeforeRender != nil {
				self.BeforeRender(&subc)
			}
			_, err = t.Parse(subc)
			if err != nil {
				return fmt.Sprintf("Parse File %v err: %v", name, err)
			}
			if ok {
				self.CachedRelation[name].Rel[tmplName] = 0
				self.CachedRelation[name].Tpl[1] = t
			} else {
				self.CachedRelation[name] = &CcRel{
					Rel: map[string]uint8{tmplName: 0},
					Tpl: [2]*htmlTpl.Template{nil, t},
				}
			}
		}
		for name, extc := range extcs {
			var t *htmlTpl.Template
			if name == tmpl.Name() {
				t = tmpl
			} else {
				t = tmpl.New(name)
			}
			if self.BeforeRender != nil {
				self.BeforeRender(&extc)
			}
			_, err = t.Parse(extc)
			if err != nil {
				return fmt.Sprintf("Parse Block %v err: %v", name, err)
			}
		}
		self.CachedRelation[tmplName] = &CcRel{
			Rel: map[string]uint8{tmplName: 0},
			Tpl: [2]*htmlTpl.Template{tmpl, nil},
		}
	} else {
		tmpl = cv.Tpl[0]
		tmpl.Funcs(funcMap)
	}
	return self.Parse(tmpl, values)
}

func (self *TemplateEx) ParseBlock(content string, subcs *map[string]string, extcs *map[string]string) {
	matches := self.blkTagRegex.FindAllStringSubmatch(content, -1)
	for _, v := range matches {
		blockName := v[1]
		content := v[2]
		(*extcs)[blockName] = self.Tag(`define "`+blockName+`"`) + self.ContainsSubTpl(content, subcs) + self.Tag(`end`)
	}
}

func (self *TemplateEx) ParseExtend(content string, extcs *map[string]string, passObject string) string {
	if passObject == "" {
		passObject = "."
	}
	matches := self.blkTagRegex.FindAllStringSubmatch(content, -1)
	for _, v := range matches {
		matched := v[0]
		blockName := v[1]
		innerStr := v[2]
		if _, ok := (*extcs)[blockName]; ok {
			content = strings.Replace(content, matched, self.Tag(`template "`+blockName+`" `+passObject), -1)
		} else {
			content = strings.Replace(content, matched, innerStr, -1)
		}
	}
	return content
}

func (self *TemplateEx) ContainsSubTpl(content string, subcs *map[string]string) string {
	matches := self.incTagRegex.FindAllStringSubmatch(content, -1)
	for _, v := range matches {
		matched := v[0]
		tmplFile := v[1]
		passObject := v[2]
		tmplFile += self.Ext
		tmplFile = self.TemplatePath(tmplFile)
		if _, ok := (*subcs)[tmplFile]; !ok {
			if v, ok := self.CachedRelation[tmplFile]; ok && v.Tpl[1] != nil {
				(*subcs)[tmplFile] = ""
				continue
			}
			b, err := self.RawContent(tmplFile)
			if err != nil {
				return fmt.Sprintf("RenderTemplate %v read err: %s", tmplFile, err)
			}
			str := string(b)
			(*subcs)[tmplFile] = "" //先登记，避免死循环
			str = self.ContainsSubTpl(str, subcs)
			(*subcs)[tmplFile] = self.Tag(`define "`+tmplFile+`"`) + str + self.Tag(`end`)
		}
		if passObject == "" {
			passObject = "."
		}
		content = strings.Replace(content, matched, self.Tag(`template "`+tmplFile+`" `+passObject), -1)
	}
	return content
}

func (self *TemplateEx) Tag(content string) string {
	return self.DelimLeft + content + self.DelimRight
}

// Include method provide to template for {{include "about"}}
func (self *TemplateEx) Include(tmplName string, fn func() htmlTpl.FuncMap, values interface{}) interface{} {
	return htmlTpl.HTML(self.Fetch(tmplName, fn, values))
}

func (self *TemplateEx) Parse(tmpl *htmlTpl.Template, values interface{}) string {
	newbytes := bytes.NewBufferString("")
	err := tmpl.Execute(newbytes, values)
	if err != nil {
		return fmt.Sprintf("Parse %v err: %v", tmpl.Name(), err)
	}

	b, err := ioutil.ReadAll(newbytes)
	if err != nil {
		return fmt.Sprintf("Parse %v err: %v", tmpl.Name(), err)
	}
	return string(b)
}

func (self *TemplateEx) RawContent(tmpl string) ([]byte, error) {
	if self.TemplateMgr != nil && self.TemplateMgr.Caches != nil {
		return self.TemplateMgr.GetTemplate(tmpl)
	}
	return ioutil.ReadFile(filepath.Join(self.TemplateDir, tmpl))
}
