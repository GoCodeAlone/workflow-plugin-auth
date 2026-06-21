package adminidentity

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

type ConformanceOptions struct {
	Handler http.Handler
	BaseURL string
	Client  *http.Client
	Routes  []RouteProbe
}

type RouteProbe struct {
	Name           string
	Method         string
	Path           string
	ExpectedStatus int
	RequireBody    bool
}

type ConformanceResult struct {
	Pass     bool
	Failures []string
}

func CheckConformance(options ConformanceOptions) ConformanceResult {
	if len(options.Routes) == 0 {
		options.Routes = DefaultRoutesForOptions(Options{})
	}
	var failures []string
	for _, probe := range options.Routes {
		status, body, err := executeProbe(options, probe)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s %s: %v", probe.Name, probe.Path, err))
			continue
		}
		if status != probe.ExpectedStatus {
			failures = append(failures, fmt.Sprintf("%s %s: status %d, want %d", probe.Name, probe.Path, status, probe.ExpectedStatus))
			continue
		}
		if probe.RequireBody && strings.TrimSpace(body) == "" {
			failures = append(failures, fmt.Sprintf("%s %s: empty body", probe.Name, probe.Path))
		}
	}
	return ConformanceResult{Pass: len(failures) == 0, Failures: failures}
}

func DefaultRoutesForOptions(options Options) []RouteProbe {
	options = normalizeOptions(options)
	return []RouteProbe{
		{Name: "identity page", Method: http.MethodGet, Path: options.PagePath, ExpectedStatus: http.StatusOK, RequireBody: true},
		{Name: "profile api", Method: http.MethodGet, Path: options.ProfilePath, ExpectedStatus: http.StatusOK, RequireBody: true},
		{Name: "credentials api", Method: http.MethodGet, Path: options.CredentialsPath, ExpectedStatus: http.StatusOK, RequireBody: true},
		{Name: "users api", Method: http.MethodGet, Path: options.UsersPath, ExpectedStatus: http.StatusOK, RequireBody: true},
	}
}

func executeProbe(options ConformanceOptions, probe RouteProbe) (int, string, error) {
	method := probe.Method
	if method == "" {
		method = http.MethodGet
	}
	if options.BaseURL != "" {
		client := options.Client
		if client == nil {
			client = http.DefaultClient
		}
		req, err := http.NewRequest(method, strings.TrimRight(options.BaseURL, "/")+cleanPath(probe.Path), nil)
		if err != nil {
			return 0, "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, "", err
		}
		return resp.StatusCode, string(body), nil
	}
	if options.Handler == nil {
		return 0, "", fmt.Errorf("missing Handler or BaseURL")
	}
	req := httptest.NewRequest(method, cleanPath(probe.Path), nil)
	rec := httptest.NewRecorder()
	options.Handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), nil
}
