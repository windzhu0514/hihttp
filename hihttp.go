package hihttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	stdurl "net/url"
	"os"
	"reflect"
	"strings"
	"time"
)

func Get(url string) (statusCode int, resp []byte, err error) {
	return defaultClient.Get(url)
}

func Post(url, contentType string, body interface{}) (statusCode int, resp []byte, err error) {
	return defaultClient.Post(url, contentType, body)
}

func PostForm(url string, data *Values) (statusCode int, resp []byte, err error) {
	return defaultClient.PostForm(url, data)
}

func Head(url string) (statusCode int, resp []byte, err error) {
	return defaultClient.Head(url)
}

// Content-Type
const (
	MIMEJSON              = "application/json"
	MIMEHTML              = "text/html"
	MIMEXML               = "application/xml"
	MIMETextXML           = "text/xml"
	MIMEPlain             = "text/plain"
	MIMEPOSTForm          = "application/x-www-form-urlencoded"
	MIMEMultipartPOSTForm = "multipart/form-data"
)

var defaultClient = NewClient()

// Client http客户端
type Client struct {
	logger Logger
	c      *http.Client

	cookies        []*http.Cookie
	requestTimeout time.Duration

	jsonEscapeHTML                    bool
	jsonIndentPrefix, jsonIndentValue string
}

type Logger interface {
	Printf(format string, v ...interface{})
}

func WithLogger(logger Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

func WithTransport(rt http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.c.Transport = rt
	}
}

func WithCheckRedirect(checkRedirect func(req *http.Request, via []*http.Request) error) ClientOption {
	return func(c *Client) {
		c.c.CheckRedirect = checkRedirect
	}
}

func WithJar(jar http.CookieJar) ClientOption {
	return func(c *Client) {
		c.c.Jar = jar
	}
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.c.Timeout = timeout
	}
}

func WithDialerTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.c.Transport.(*http.Transport).DialContext = (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}
}

func WithoutForceAttemptHTTP2() ClientOption {
	return func(c *Client) {
		c.c.Transport.(*http.Transport).ForceAttemptHTTP2 = false
	}
}

type ClientOption func(c *Client)

func NewClient(opts ...ClientOption) *Client {
	var c Client
	c.c = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	c.c.Jar, _ = cookiejar.New(nil)

	c.logger = log.New(os.Stderr, "", log.Lshortfile|log.Ldate|log.Lmicroseconds)

	for _, opt := range opts {
		opt(&c)
	}

	return &c
}

func (c *Client) Do(req *Request) (*Response, error) {
	// body
	var body io.Reader
	if req.body != nil {
		switch data := req.body.(type) {
		case io.Reader:
			body = data.(io.Reader)
		case []byte:
			bf := bytes.NewBuffer(data)
			body = ioutil.NopCloser(bf)
		case string:
			bf := bytes.NewBufferString(data)
			body = ioutil.NopCloser(bf)
		default:
			buf := bytes.NewBuffer(nil)
			enc := json.NewEncoder(buf)
			req.SetHead("Content-Type", MIMEJSON)
			if err := enc.Encode(data); err != nil {
				return nil, err
			}
		}
	}

	ct := req.heads.Get("Content-Type")
	if ct == "" {
		req.SetHead("Content-Type", detectContentType(req.body))
	}

	reqURL, err := stdurl.Parse(req.url)
	if err != nil {
		return nil, err
	}

	queryParam := req.queryParams.Encode()
	if req.queryParams != nil {
		if reqURL.RawQuery == "" {
			reqURL.RawQuery = queryParam
		} else {
			reqURL.RawQuery = reqURL.RawQuery + "&" + queryParam
		}
	}

	url := reqURL.String()

	rawReq, err := http.NewRequest(req.method, url, body)
	if err != nil {
		return nil, err
	}

	if req.ctx != nil {
		rawReq = rawReq.WithContext(req.ctx)
	}

	if req.responseTimeout > 0 {
		ctx, cancel := context.WithTimeout(rawReq.Context(), req.responseTimeout)
		defer cancel()
		rawReq.WithContext(ctx)
	}

	for key, value := range req.heads {
		rawReq.Header[key] = value
	}

	if len(req.cookies) > 0 {
		c.c.Jar.SetCookies(reqURL, req.cookies)
	}

	resp, err := c.c.Do(rawReq)
	wrapResp := &Response{}
	wrapResp.r = resp

	return wrapResp, err
}

func detectContentType(body interface{}) string {
	contentType := MIMEPlain
	kind := reflect.Indirect(reflect.ValueOf(body)).Type().Kind()
	switch kind {
	case reflect.Struct, reflect.Map, reflect.Slice:
		contentType = MIMEJSON
	case reflect.String:
		contentType = MIMEPlain
	default:
		if b, ok := body.([]byte); ok {
			contentType = http.DetectContentType(b)
		}
	}

	return contentType
}

func (c *Client) Get(url string) (statusCode int, resp []byte, err error) {
	req := NewRequest(http.MethodGet, url)

	var response *Response
	response, err = c.Do(req)
	if err != nil {
		return
	}

	statusCode = response.StatusCode()
	resp, err = response.Body()

	return
}

func (c *Client) Post(url, contentType string, body interface{}) (
	statusCode int, resp []byte, err error) {
	req := NewRequest(http.MethodPost, url)
	req.SetBody(contentType, body)

	var response *Response
	response, err = c.Do(req)
	if err != nil {
		return
	}

	statusCode = response.StatusCode()
	resp, err = response.Body()

	return
}

func (c *Client) PostForm(url string, data *Values) (
	statusCode int, resp []byte, err error) {
	req := NewRequest(http.MethodPost, url)
	req.SetBody("application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()))

	var response *Response
	response, err = c.Do(req)
	if err != nil {
		return
	}

	statusCode = response.StatusCode()
	resp, err = response.Body()

	return
}

func (c *Client) Head(url string) (statusCode int, resp []byte, err error) {
	req := NewRequest(http.MethodHead, url)

	var response *Response
	response, err = c.Do(req)
	if err != nil {
		return
	}

	statusCode = response.StatusCode()
	resp, err = response.Body()

	return
}

func (c *Client) transport() (*http.Transport, error) {
	if transport, ok := c.c.Transport.(*http.Transport); ok {
		return transport, nil
	}
	return nil, errors.New("client transport type is not *http.Transport")
}

// SetProxy 设置代理
// Proxy：http://127.0.0.1:8888
func (c *Client) SetProxy(proxyURL string) *Client {
	c.SetProxySelector(ProxySelectorFunc(func(req *http.Request) (*stdurl.URL, error) {
		return stdurl.Parse(proxyURL)
	}))
	return c
}

// SetAuthProxy 设置认证代理
func (c *Client) SetAuthProxy(proxyURL, username, password string, urls ...string) *Client {
	c.SetProxySelector(ProxySelectorFunc(func(req *http.Request) (*stdurl.URL, error) {
		u, _ := stdurl.Parse(proxyURL)
		u.User = stdurl.UserPassword(username, password)
		return u, nil
	}))
	return c
}

// SetProxySelector 设置代理选择器
func (c *Client) SetProxySelector(selector ProxySelector) *Client {
	transport, err := c.transport()
	if err != nil {
		c.logger.Printf("%s", err.Error())
		return c
	}

	transport.Proxy = selector.ProxyFunc
	return c
}

// SetCookie 添加cookiec
func (c *Client) AddCookie(cookie *http.Cookie) *Client {
	c.cookies = append(c.cookies, cookie)
	return c
}

// SetCookies 添加cookies
func (c *Client) AddCookies(cookies []*http.Cookie) *Client {
	c.cookies = append(c.cookies, cookies...)
	return c
}

//// SetJsontEscapeHTML 设置json编码时是否转义HTML字符
//func (c *Client) SetJsontEscapeHTML(jsonEscapeHTML bool) *Client {
//	c.jsonEscapeHTML = jsonEscapeHTML
//	return c
//}
//
//// SetJsontIndent 设置json编码时的缩进格式 都为空不进行缩进
//func (c *Client) SetJsontIndent(prefix, indent string) *Client {
//	c.jsonIndentPrefix = prefix
//	c.jsonIndentValue = indent
//	return c
//}

type ValueOption func(urlValue *Value)

func WithOmitEmpty() ValueOption {
	return func(urlValue *Value) {
		urlValue.IsOmitEmpty = true
	}
}

type Value struct {
	Key         string
	Values      []string
	IsOmitEmpty bool
}

// Values maps a string key to a list of values.
// It is typically used for query parameters and form values.
// Unlike in the http.Header map, the keys in a Values map
// are case-sensitive.

type Values struct {
	keyValues map[string]*Value
	addOrder  []string
}

func NewValues() *Values {
	return &Values{
		keyValues: make(map[string]*Value),
		addOrder:  make([]string, 0),
	}
}

func (v *Values) Get(key string) string {
	if v.keyValues == nil {
		return ""
	}

	vs := v.keyValues[key]
	if len(vs.Values) == 0 {
		return ""
	}
	return vs.Values[0]
}

func (v *Values) Set(key, value string, opts ...ValueOption) {
	if v.keyValues == nil {
		return
	}

	if _, ok := v.keyValues[key]; !ok {
		v.addOrder = append(v.addOrder, key)
	}

	newValue := &Value{Key: key, Values: []string{value}}
	for _, opt := range opts {
		opt(newValue)
	}
	v.keyValues[key] = newValue
}

func (v *Values) Add(key, value string, opts ...ValueOption) {
	if v.keyValues == nil {
		return
	}

	_, ok := v.keyValues[key]
	if ok {
		v.keyValues[key].Values = append(v.keyValues[key].Values, value)
		for _, opt := range opts {
			opt(v.keyValues[key])
		}
	} else {
		newValue := &Value{Key: key, Values: []string{value}}
		for _, opt := range opts {
			opt(newValue)
		}
		v.keyValues[key] = newValue
		v.addOrder = append(v.addOrder, key)
	}
}

func (v *Values) AddValues(values ...Value) {
	if v.keyValues == nil {
		return
	}

	for _, value := range values {
		_, ok := v.keyValues[value.Key]
		if ok {
			v.keyValues[value.Key].Values =
				append(v.keyValues[value.Key].Values, value.Values...)
		} else {
			v.keyValues[value.Key] = &value
			v.addOrder = append(v.addOrder, value.Key)
		}
	}
}

func (v *Values) Del(key string) {
	if v.keyValues == nil {
		return
	}

	_, ok := v.keyValues[key]
	if ok {
		for i, oldKey := range v.addOrder {
			if oldKey == key {
				v.addOrder = append(v.addOrder[:i], v.addOrder[i+1:]...)
			}
		}
		delete(v.keyValues, key)
	}
}

func (v *Values) Encode() (queryParam string) {
	if v.keyValues == nil {
		return ""
	}

	var buf strings.Builder
	for _, key := range v.addOrder {
		values := v.keyValues[key]
		if values.IsOmitEmpty && len(values.Values) == 0 {
			continue
		}

		keyEscaped := stdurl.QueryEscape(key)
		for _, v := range values.Values {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(stdurl.QueryEscape(v))
		}
	}

	return buf.String()
}

func (v *Values) copyFrom(dest *Values) {
	if dest == nil {
		return
	}

	for _, key := range dest.addOrder {
		values := dest.keyValues[key]
		if values.IsOmitEmpty && len(values.Values) == 0 {
			continue
		}
		v.AddValues(*values)
	}
}

// Request http请求
type Request struct {
	//r      *http.Request
	//err    error
	//url    string
	//	method stringcancel context.CancelFunc
	url         string
	method      string
	heads       http.Header
	queryParams *Values
	cookies     []*http.Cookie
	ctx         context.Context
	body        interface{}

	responseTimeout time.Duration

	//jsonEscapeHTML                    bool
	//jsonIndentPrefix, jsonIndentValue string

	//files map[string]string
	///resp  *http.Response
	//dump  []byte

	//client *Client
}

// NewRequest 新建一个默认Client的请求
func NewRequest(method, url string) *Request {
	wrapReq := Request{
		method:      method,
		url:         url,
		heads:       make(http.Header),
		queryParams: NewValues(),
	}
	return &wrapReq
}

//func NewRequestWithTimeout(method, url string, timeout time.Duration) *Request {
//	var wrapReq Request
//	ctx, cancel := context.WithTimeout(context.Background(), timeout)
//	wrapReq.r, wrapReq.err = http.NewRequestWithContext(ctx, method, url, nil)
//	wrapReq.cancel = cancel
//	return &wrapReq
//}

// SetHead 添加head 自动规范化
func (r *Request) AddHead(key, value string) *Request {
	r.heads.Set(key, value)
	return r
}

func (r *Request) AddRawHead(key, value string) *Request {
	r.heads[key] = append(r.heads[key], value)
	return r
}

func (r *Request) SetHead(key, value string) *Request {
	r.heads.Set(key, value)
	return r
}

// SetRawHead 添加heads 不自动规范化
// SetRawHead 添加heads 不自动规范化
func (r *Request) SetRawHead(key, value string) *Request {
	r.heads[key] = []string{value}
	return r
}

// SetHeads 添加heads 自动规范化
func (r *Request) AddHeads(headers http.Header) *Request {
	for key, values := range headers {
		for _, value := range values {
			r.AddHead(key, value)
		}
	}
	return r
}

// SetRawHeads 添加heads 不自动规范化
func (r *Request) AddRawHeads(headers http.Header) *Request {
	for key, values := range headers {
		for _, value := range values {
			r.AddRawHead(key, value)
		}
	}
	return r
}

// SetParam 添加请求参数
func (r *Request) QueryParam(key, value string) *Request {
	r.queryParams.Add(key, value)
	return r
}

func (r *Request) QueryParams(values *Values) *Request {
	r.queryParams.copyFrom(values)
	return r
}

// WithContext 设置请求的Context
func (r *Request) WithContext(ctx context.Context) *Request {
	r.ctx = ctx
	return r
}

// AddCookie 添加cookie
func (r *Request) AddCookie(cookie *http.Cookie) *Request {
	r.cookies = append(r.cookies, cookie)
	return r
}

func (r *Request) SetTimeout(timeout time.Duration) *Request {
	r.responseTimeout = timeout
	return r
}

// SetBody 设置body
func (r *Request) SetBody(contentType string, body interface{}) *Request {
	r.heads.Set("Content-Type", contentType)
	r.body = body
	return r
}

//// SetJsontEscapeHTML 设置该请求json编码时是否转义HTML字符
//func (r *Request) SetJsontEscapeHTML() *Request {
//	r.jsonEscapeHTML = true
//	return r
//}
//
//// SetJsontIndent 设置该请求json编码时的缩进格式 都为空不进行缩进
//func (r *Request) SetJsontIndent(prefix, indent string) *Request {
//	r.jsonIndentPrefix = prefix
//	r.jsonIndentValue = indent
//	return r
//}

// Response 请求结果
type Response struct {
	r *http.Response
	//err error
}

// StatusCode 返回状态码
func (r *Response) StatusCode() int {
	if r == nil || r.r == nil {
		return 0
	}

	return r.r.StatusCode
}

// Headers 返回请求结果的heads
func (r *Response) Headers() http.Header {
	if r == nil || r.r == nil {
		return nil
	}

	return r.r.Header
}

// Cookie 返回请求结果的Cookie
func (r *Response) Cookies() []*http.Cookie {
	if r == nil || r.r == nil {
		return nil
	}

	return r.r.Cookies()
}

// Location 返回重定向地址
func (r *Response) Location() (string, error) {
	if r == nil || r.r == nil {
		return "", errors.New("hihttp:http response is nil pointer")
	}

	location, err := r.r.Location()
	if err != nil {
		return "", err
	}

	return location.String(), nil
}

// Body 返回请求结果的body 超时时间包括body的读取 请求结束后要尽快读取
func (r *Response) Body() (body []byte, err error) {
	if r == nil || r.r == nil {
		return nil, errors.New("hihttp:http response is invalid")
	}

	if r.r.Body == nil {
		return nil, nil
	}

	defer r.r.Body.Close()
	if r.r.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(r.r.Body)
		if err != nil {
			return nil, err
		}
		body, err = ioutil.ReadAll(reader)
	} else {
		body, err = ioutil.ReadAll(r.r.Body)
	}

	return
}

// FromJSON 解析请求结果JSON到v
func (r *Response) JsonUnmarshal(v interface{}) error {
	resp, err := r.Body()
	if err != nil {
		return err
	}

	return json.Unmarshal(resp, v)
}

// ToFile 保存请求结果到文件
func (r *Response) ToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := r.Body()
	if err != nil {
		return err
	}

	_, err = io.Copy(f, bytes.NewReader(resp))
	return err
}

// SetProxy 设置默认Client的代理
// Proxy：http://127.0.0.1:8888
func SetProxy(proxyURL string) {
	SetProxySelector(ProxySelectorFunc(func(req *http.Request) (*stdurl.URL, error) {
		return stdurl.ParseRequestURI(proxyURL)
	}))
}

// SetAuthProxy 设置默认Client的认证代理
func SetAuthProxy(proxyURL, username, password string) {
	SetProxySelector(ProxySelectorFunc(func(req *http.Request) (*stdurl.URL, error) {
		u, _ := stdurl.ParseRequestURI(proxyURL)
		u.User = stdurl.UserPassword(username, password)
		return u, nil
	}))
}

// SetProxySelector 设置默认Client的代理选择器
func SetProxySelector(selector ProxySelector) {
	defaultClient.SetProxySelector(selector)
}

// HTTPProxy http代理
type HTTPProxy struct {
	isAuthProxy bool
	// isAuthProxy=false
	proxyURL string

	// isAuthProxy=true
	username string
	password string
	ip       string
	port     string
}

// IsZero 检查代理信息是否有效
func (p *HTTPProxy) IsZero() bool {
	return p.isAuthProxy && p.ip == "" || !p.isAuthProxy && p.proxyURL == ""
}

// ProxySelector 代理选择器接口
type ProxySelector interface {
	ProxyFunc(req *http.Request) (*stdurl.URL, error)
}

// HostnameProxy 设置指定的URL使用指定的代理
var HostnameProxy = HostnameProxySelector{proxys: make(map[string]HTTPProxy)}

// HostnameProxySelector 保存URL和对应的代理
type HostnameProxySelector struct {
	proxys map[string]HTTPProxy
}

// SetProxy 设置指定URL使用代理
func (p *HostnameProxySelector) SetProxy(proxyURL string, urls ...string) {
	hp := HTTPProxy{isAuthProxy: false, proxyURL: proxyURL}

	for _, rawURL := range urls {
		URL, err := stdurl.Parse(rawURL)
		if err == nil {
			p.proxys[URL.Hostname()] = hp
		}
	}

}

// SetAuthProxy 设置指定URL使用认证代理
func (p *HostnameProxySelector) SetAuthProxy(username, password, ip, port string, urls ...string) {
	var hp HTTPProxy
	hp.isAuthProxy = true
	hp.username = username
	hp.password = password
	hp.ip = ip
	hp.port = port

	for _, rawURL := range urls {
		URL, err := stdurl.Parse(rawURL)
		if err == nil {
			p.proxys[URL.Hostname()] = hp
		}
	}

}

// ProxyFunc 实现ProxySelector接口
func (p *HostnameProxySelector) ProxyFunc(req *http.Request) (*stdurl.URL, error) {
	if req == nil || req.URL == nil || len(p.proxys) == 0 {
		return nil, nil
	}

	hp, ok := p.proxys[req.URL.Hostname()]
	if !ok || hp.IsZero() {
		return nil, nil
	}

	if hp.isAuthProxy {
		proxyURL := "http://" + hp.ip + ":" + hp.port
		u, _ := stdurl.Parse(proxyURL)
		u.User = stdurl.UserPassword(hp.username, hp.password)
		return u, nil
	}

	u, _ := stdurl.Parse(hp.proxyURL)
	return u, nil
}

// ProxySelectorFunc 转换代理函数，实现ProxySelector接口
type ProxySelectorFunc func(req *http.Request) (*stdurl.URL, error)

// ProxyFunc 实现ProxySelector接口
func (s ProxySelectorFunc) ProxyFunc(req *http.Request) (*stdurl.URL, error) {
	return s(req)
}
