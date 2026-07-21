// scraper_go.go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
)

type Result struct {
	Status  string      `json:"status"`
	Data    *PageData   `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

type PageData struct {
	Title           string   `json:"title"`
	URL             string   `json:"url"`
	Forms           []Form   `json:"forms"`
	Cookies         []Cookie `json:"cookies"`
	LocalStorage    string   `json:"local_storage"`
	SessionStorage  string   `json:"session_storage"`
	Links           []string `json:"links"`
	Scripts         []string `json:"scripts"`
	Images          []string `json:"images"`
	ScreenshotBase64 string  `json:"screenshot_base64"`
}

type Form struct {
	Action string  `json:"action"`
	Method string  `json:"method"`
	Inputs []Input `json:"inputs"`
}

type Input struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("URL required")
	}
	url := os.Args[1]

	l := launcher.New().
		Headless(true).
		Set("disable-gpu").
		Set("no-sandbox").
		Set("disable-dev-shm-usage").
		Set("window-size", "1920,1080").
		Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	if proxy := os.Getenv("PROXY_ADDRESS"); proxy != "" {
		l.Set("proxy-server", proxy)
	}

	browser := rod.New().ControlURL(l.MustLaunch()).MustConnect()
	defer browser.MustClose()

	page := stealth.MustPage(browser)
	page.MustWaitLoad()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := page.Timeout(30 * time.Second).Navigate(url)
	if err != nil {
		result := Result{Status: "error", Message: err.Error()}
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}

	time.Sleep(3 * time.Second)

	var data PageData
	data.URL = url
	data.Title = page.MustInfo().Title

	var forms []Form
	els := page.MustElements("form")
	for _, el := range els {
		action := el.MustAttribute("action")
		method := el.MustAttribute("method")
		var inputs []Input
		inputEls := el.MustElements("input")
		for _, inp := range inputEls {
			name := inp.MustAttribute("name")
			typ := inp.MustAttribute("type")
			val := inp.MustAttribute("value")
			inputs = append(inputs, Input{
				Name:  safeStr(name),
				Type:  safeStr(typ),
				Value: safeStr(val),
			})
		}
		forms = append(forms, Form{
			Action: safeStr(action),
			Method: safeStr(method),
			Inputs: inputs,
		})
	}
	data.Forms = forms

	cookies, _ := page.Cookies([]proto.NetworkCookieParam{})
	for _, c := range cookies {
		data.Cookies = append(data.Cookies, Cookie{
			Name:   c.Name,
			Value:  c.Value,
			Domain: c.Domain,
			Path:   c.Path,
		})
	}

	local, _ := page.Evaluate("() => JSON.stringify(localStorage)")
	data.LocalStorage = local.String()
	session, _ := page.Evaluate("() => JSON.stringify(sessionStorage)")
	data.SessionStorage = session.String()

	links, _ := page.Elements("a")
	for _, l := range links {
		href := l.MustAttribute("href")
		if href != nil {
			data.Links = append(data.Links, *href)
		}
	}
	scripts, _ := page.Elements("script")
	for _, s := range scripts {
		src := s.MustAttribute("src")
		if src != nil {
			data.Scripts = append(data.Scripts, *src)
		}
	}
	imgs, _ := page.Elements("img")
	for _, img := range imgs {
		src := img.MustAttribute("src")
		if src != nil {
			data.Images = append(data.Images, *src)
		}
	}

	screenshot, _ := page.Screenshot(true, nil)
	data.ScreenshotBase64 = base64.StdEncoding.EncodeToString(screenshot)

	result := Result{Status: "success", Data: &data}
	json.NewEncoder(os.Stdout).Encode(result)
}

func safeStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
