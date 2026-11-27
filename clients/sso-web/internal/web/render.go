package web

import (
	"bytes"
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// templates holds one parsed set per page, each with the layout.
type templates struct {
	byName map[string]*template.Template
}

func parseTemplates() (*templates, error) {
	funcs := template.FuncMap{
		"year": func() int { return time.Now().Year() },
		"list": func(v ...any) []any { return v },
	}
	layout, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html")
	if err != nil {
		return nil, err
	}
	t := &templates{byName: map[string]*template.Template{}}
	for _, name := range []string{"home", "message"} {
		c, err := layout.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := c.ParseFS(templateFS, "templates/"+name+".html"); err != nil {
			return nil, err
		}
		t.byName[name] = c
	}
	return t, nil
}

func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(sub)
	return http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		files.ServeHTTP(w, r)
	}))
}

// page is what every template gets.
type page struct {
	Site    string
	Title   string
	User    string // the signed-in person, or ""
	Version string
	Data    any
}

// flash is a message for the next page.
type flash struct {
	Kind  string // ok, warn or error
	Title string
	Lines []flashLine
}

type flashLine struct {
	OK   bool
	Text string
}

func (s *Server) render(w http.ResponseWriter, status int, name, title, user string, data any) {
	var buf bytes.Buffer
	err := s.pages.byName[name].ExecuteTemplate(&buf, "layout.html", page{
		Site: s.Title, Title: title, User: user, Version: s.Version, Data: data,
	})
	if err != nil {
		s.Log.Error("rendering a page", "page", name, "error", err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type messageView struct {
	Heading string
	Message string
	Link    string // a way on, if any
	LinkTo  string
}

// Fail shows an error page. It is also how sign-in providers report errors.
func (s *Server) Fail(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	user := ""
	if sess, ok := s.session(r); ok {
		user = sess.User
	}
	v := messageView{Heading: title, Message: message}
	if status != http.StatusNotFound {
		v.Link, v.LinkTo = "Start again", "/"
	} else {
		v.Link, v.LinkTo = "Go to your addresses", "/"
	}
	s.render(w, status, "message", title, user, v)
}
