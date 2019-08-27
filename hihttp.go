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
	"strings"
	"time"
)

// Get 使用默认Client发送Get请求
func Get(url string) (statusCode int, resp []byte, err error) {
	req := defaultClient.Get(url)

	var response *Response
	response, err = req.Do()
	if err != nil {
		return
	}

	statusCode = response.StatusCode()
	resp, err = response.Body()

	return
}

// Post 使用默认Client发送Get请求
func Post(url, contentType string, body interface{}) (statusCode int, resp []byte, err error) {

	req := defaultClient.Post(url)
	if err != nil {
		return
	}

	req.SetHead("Content-Type", contentType)
	req.SetBody(body)

	var response *Response
	response, err = req.Do()
	if err != nil {
		return
	}

	statusCode = response.resp.StatusCode
	resp, err = response.Body()

	return
}

// SetTimeout 设置默认Client的超时时间
func SetTimeout(timeout time.Duration) {
	defaultClient.SetTimeout(timeout)
}

// SetDailTimeout 设置默认Client的拨号超时时间
func SetDailTimeout(timeout time.Duration) {
	defaultClient.SetDailTimeout(timeout)
}

// SetRequestTimeout 设置默认Client的请求超时时间
func SetRequestTimeout(timeout time.Duration) {
	defaultClient.SetRequestTimeout(timeout)
}

// SetCookieJar 设置默认Client的Cookiejar
func SetCookieJar(jar http.CookieJar) {
	defaultClient.SetCookieJar(jar)
}

// SetKeepParamAddOrder 设置默认Client请求发送时参数保持添加顺序
func SetKeepParamAddOrder(keepParamAddOrder bool) {
	defaultClient.SetDisableKeepAlives(keepParamAddOrder)
}

// SetDisableKeepAlives 设置默认Client的DisableKeepAlives
func SetDisableKeepAlives(disableKeepAlives bool) {
	defaultClient.SetDisableKeepAlives(disableKeepAlives)
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

// Content-Type
const (
	MIMEJSON              = "application/json"
	MIMEHTML              = "text/html"
	MIMEXML               = "application/xml"
	MIMETextXML           = "text/xml"
	MIMEPlain             = "text/plain"
	MIMEPOSTForm          = "application/x-www-form-urlencoded"
	MIMEMultipartPOSTForm = "multipart/form-data"
	MIMEXPROTOBUF         = "application/x-protobuf"
	MIMEXMSGPACK          = "application/x-msgpack"
	MIMEMSGPACK           = "application/msgpack"
	MIMEYAML              = "application/x-yaml"
)

var defaultClient = NewClient()

// Client http客户端
type Client struct {
	log *log.Logger
	*http.Client
	dialer         *net.Dialer
	cookies        []*http.Cookie
	requestTimeout time.Duration

	keepParamAddOrder                 bool
	jsonEscapeHTML                    bool
	jsonIndentPrefix, jsonIndentValue string
}

// NewClient 新建一个Client
func NewClient() *Client {
	var c Client
	c.dialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	c.Client = &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           c.dialer.DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	c.Client.Jar, _ = cookiejar.New(nil)

	c.log = log.New(os.Stderr, "", log.Ldate|log.Lmicroseconds)

	return &c
}

// NewRequest 新建一个请求
func (c *Client) NewRequest(method, url string) *Request {
	var req Request
	req.client = c
	req.method = method
	req.url = url
	req.heads = make(http.Header)
	req.params = make(stdurl.Values)

	return &req
}

// Get 新建Get请求
func (c *Client) Get(url string) *Request {
	return c.NewRequest(url, "GET")
}

// Post 新建Post请求
func (c *Client) Post(url string) *Request {
	return c.NewRequest(url, "POST")
}

// Put 新建Put请求
func (c *Client) Put(url string) *Request {
	return c.NewRequest(url, "PUT")
}

// Delete 新建Delete请求
func (c *Client) Delete(url string) *Request {
	return c.NewRequest(url, "DELETE")
}

// Head 新建Head请求
func (c *Client) Head(url string) *Request {
	return c.NewRequest(url, "HEAD")
}

// SetTransport 给Client设置新的transport
func (c *Client) SetTransport(transport http.RoundTripper) *Client {
	if transport != nil {
		c.Transport = transport
	}

	return c
}

func (c *Client) transport() (*http.Transport, error) {
	if transport, ok := c.Transport.(*http.Transport); ok {
		return transport, nil
	}
	return nil, errors.New("client transport type is not *http.Transport")
}

// SetMaxConnsPerHost 设置每个Host的最大连接数 默认无限制
func (c *Client) SetMaxConnsPerHost(n int) *Client {
	transport, err := c.transport()
	if err != nil {
		c.log.Println(err.Error())
		return c
	}

	transport.MaxConnsPerHost = n
	return c
}

// SetMaxIdleConnsPerHost 设置每个Host的最大空闲连接数 默认为2个
func (c *Client) SetMaxIdleConnsPerHost(n int) *Client {
	transport, err := c.transport()
	if err != nil {
		c.log.Println(err.Error())
		return c
	}

	transport.MaxIdleConnsPerHost = n
	return c
}

// SetMaxIdleConns 设置最大空闲连接数 默认无限制
func (c *Client) SetMaxIdleConns(n int) *Client {
	transport, err := c.transport()
	if err != nil {
		c.log.Println(err.Error())
		return c
	}

	transport.MaxIdleConns = n
	return c
}

// SetTimeout 设置Client的超时时间
func (c *Client) SetTimeout(timeout time.Duration) *Client {
	c.Timeout = timeout
	return c
}

// SetDailTimeout 设置拨号超时间
func (c *Client) SetDailTimeout(timeout time.Duration) *Client {
	transport, err := c.transport()
	if err != nil {
		c.log.Println(err.Error())
		return c
	}

	c.dialer.Timeout = timeout
	transport.DialContext = c.dialer.DialContext
	return c
}

// SetRequestTimeout 设置请求超时时间
func (c *Client) SetRequestTimeout(timeout time.Duration) *Client {
	c.requestTimeout = timeout
	return c
}

// SetDisableKeepAlives 设置禁用HTTP keep-alives
func (c *Client) SetDisableKeepAlives(disableKeepAlives bool) *Client {
	transport, err := c.transport()
	if err != nil {
		c.log.Println(err.Error())
		return c
	}

	transport.DisableKeepAlives = disableKeepAlives
	return c
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
		c.log.Println(err.Error())
		return c
	}

	transport.Proxy = selector.ProxyFunc
	return c
}

// SetCheckRedirect 设置重定向函数
func (c *Client) SetCheckRedirect(cr func(req *http.Request, via []*http.Request) error) *Client {
	c.CheckRedirect = cr
	return c
}

// SetCookieJar 设置CookieJar 设置为nil禁用cookie
func (c *Client) SetCookieJar(jar http.CookieJar) *Client {
	c.Client.Jar = jar
	return c
}

// SetCookie 添加cookie
func (c *Client) SetCookie(cookie *http.Cookie) *Client {
	c.cookies = append(c.cookies, cookie)
	return c
}

// SetCookies 添加cookies
func (c *Client) SetCookies(cookies []*http.Cookie) *Client {
	c.cookies = append(c.cookies, cookies...)
	return c
}

// SetJsontEscapeHTML 设置json编码时是否转义HTML字符
func (c *Client) SetJsontEscapeHTML(jsonEscapeHTML bool) *Client {
	c.jsonEscapeHTML = jsonEscapeHTML
	return c
}

// SetJsontIndent 设置json编码时的缩进格式 都为空不进行缩进
func (c *Client) SetJsontIndent(prefix, indent string) *Client {
	c.jsonIndentPrefix = prefix
	c.jsonIndentValue = indent
	return c
}

// KeepParamAddOrder 设置请求发送时参数保持添加顺序
func (c *Client) KeepParamAddOrder(keepParamAddOrder bool) *Client {
	c.keepParamAddOrder = keepParamAddOrder
	return c
}

// Request http请求
type Request struct {
	url         string
	method      string
	heads       http.Header
	params      stdurl.Values
	paramsOrder []string
	body        interface{}
	cookies     []*http.Cookie

	dialTimeout                       time.Duration
	responseTimeout                   time.Duration
	keepParamAddOrder                 bool
	jsonEscapeHTML                    bool
	jsonIndentPrefix, jsonIndentValue string

	checkRedirect func(req *http.Request, via []*http.Request) error
	ctx           context.Context

	files map[string]string
	resp  *http.Response
	dump  []byte

	client *Client
}

// NewRequest 新建一个默认Client的请求
func NewRequest(method, url string) *Request {
	return defaultClient.NewRequest(method, url)
}

// SetHead 添加head 自动规范化
func (r *Request) SetHead(key, value string) *Request {
	r.heads.Set(key, value)
	return r
}

// SetHeads 添加heads 自动规范化
func (r *Request) SetHeads(headers http.Header) *Request {
	for key, values := range headers {
		for _, value := range values {
			r.heads.Set(key, value)
		}
	}
	return r
}

// SetRawHead 添加heads 不自动规范化
func (r *Request) SetRawHead(key, value string) *Request {
	r.heads[key] = []string{value}
	return r
}

// SetRawHeads 添加heads 不自动规范化
func (r *Request) SetRawHeads(heads map[string]string) *Request {
	for key, value := range heads {
		r.heads[key] = []string{value}
	}
	return r
}

// SetParam 添加请求参数
func (r *Request) SetParam(key, value string) *Request {
	r.params.Add(key, value)
	r.paramsOrder = append(r.paramsOrder, key)
	return r
}

// KeepParamAddOrder 设置该请求发送时参数保持添加顺序
func (r *Request) KeepParamAddOrder(keepParamAddOrder bool) *Request {
	r.keepParamAddOrder = keepParamAddOrder
	return r
}

// SetCheckRedirect 设置该请求的重定向函数
func (r *Request) SetCheckRedirect(checkRedirect func(req *http.Request, via []*http.Request) error) *Request {
	r.checkRedirect = checkRedirect
	return r
}

// WithContext 设置请求的Context
func (r *Request) WithContext(ctx context.Context) *Request {
	r.ctx = ctx
	return r
}

// SetCookie 添加cookie
func (r *Request) SetCookie(cookie *http.Cookie) *Request {
	r.cookies = append(r.cookies, cookie)
	return r
}

// SetBody 设置body
func (r *Request) SetBody(body interface{}) *Request {
	r.body = body
	return r
}

// SetJsontEscapeHTML 设置该请求json编码时是否转义HTML字符
func (r *Request) SetJsontEscapeHTML() *Request {
	r.jsonEscapeHTML = true
	return r
}

// SetJsontIndent 设置该请求json编码时的缩进格式 都为空不进行缩进
func (r *Request) SetJsontIndent(prefix, indent string) *Request {
	r.jsonIndentPrefix = prefix
	r.jsonIndentValue = indent
	return r
}

// Do 发送请求和获取结果
func (r *Request) Do() (*Response, error) {
	if r.checkRedirect != nil {
		r.client.CheckRedirect = r.checkRedirect
	}

	defer func() {
		r.client.CheckRedirect = nil
	}()

	// body
	var body io.Reader
	switch data := r.body.(type) {
	case io.Reader:
		body = data.(io.Reader)
	case []byte:
		bf := bytes.NewBuffer(data)
		body = ioutil.NopCloser(bf)
	case string:
		bf := bytes.NewBufferString(data)
		body = ioutil.NopCloser(bf)
	default:
		// switch reflect.TypeOf(data).Kind() {
		// case reflect.Struct,reflect.Map,reflect.Slice:
		buf := bytes.NewBuffer(nil)
		enc := json.NewEncoder(buf)
		if r.jsonEscapeHTML || r.client.jsonEscapeHTML {
			enc.SetEscapeHTML(true)
		}

		if r.client.jsonIndentPrefix != "" || r.client.jsonIndentValue != "" {
			enc.SetIndent(r.client.jsonIndentPrefix, r.client.jsonIndentValue)
		}

		if r.jsonIndentPrefix != "" || r.jsonIndentValue != "" {
			enc.SetIndent(r.jsonIndentPrefix, r.jsonIndentValue)
		}

		if err := enc.Encode(data); err != nil {
			return nil, err
		}
		body = ioutil.NopCloser(buf)
		//}
	}

	reqURL, err := stdurl.Parse(r.url)
	if err != nil {
		return nil, err
	}

	var queryParam string
	if r.keepParamAddOrder || r.client.keepParamAddOrder {
		len := len(r.paramsOrder)
		var buf strings.Builder
		for i := 0; i < len; i++ {
			vs := r.params[r.paramsOrder[i]]
			keyEscaped := stdurl.QueryEscape(r.paramsOrder[i])
			for _, v := range vs {
				if buf.Len() > 0 {
					buf.WriteByte('&')
				}
				buf.WriteString(keyEscaped)
				buf.WriteByte('=')
				buf.WriteString(stdurl.QueryEscape(v))
			}
		}
		queryParam = buf.String()
	} else {
		queryParam = r.params.Encode()
	}

	if len(queryParam) > 0 {
		if reqURL.RawQuery == "" {
			reqURL.RawQuery = queryParam
		} else {
			reqURL.RawQuery = reqURL.RawQuery + "&" + queryParam
		}
	}

	r.url = reqURL.String()

	req, err := http.NewRequest(r.method, r.url, body)
	if err != nil {
		return nil, err
	}

	if r.ctx != nil {
		req = req.WithContext(r.ctx)
	}

	for key, value := range r.heads {
		req.Header[key] = value
	}

	if len(r.cookies) > 0 {
		r.client.Jar.SetCookies(req.URL, r.cookies)
	}

	var resp Response
	resp.resp, err = r.client.Do(req)

	return &resp, err
}

// Response 请求结果
type Response struct {
	resp *http.Response
	err  error
}

// StatusCode 返回状态码
func (r *Response) StatusCode() int {
	if r == nil || r.resp == nil {
		return 0
	}

	return r.resp.StatusCode
}

// Headers 返回请求结果的heads
func (r *Response) Headers() http.Header {
	if r == nil || r.resp == nil {
		return nil
	}

	return r.resp.Header
}

// Cookie 返回请求结果的Cookie
func (r *Response) Cookie() []*http.Cookie {
	if r == nil || r.resp == nil {
		return nil
	}

	return r.resp.Cookies()
}

// Location 返回重定向地址
func (r *Response) Location() (string, error) {
	if r == nil || r.resp == nil {
		return "", errors.New("hihttp:http response is nil pointer")
	}

	location, err := r.resp.Location()
	if err != nil {
		return "", err
	}

	return location.String(), nil
}

// Body 返回请求结果的body 超时时间包括body的读取 请求结束后要尽快读取
func (r *Response) Body() (body []byte, err error) {
	if r == nil || r.resp == nil {
		return nil, errors.New("hihttp:http response is nil pointer")
	}

	if r.resp.Body == nil {
		return nil, nil
	}

	defer r.resp.Body.Close()
	if r.resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(r.resp.Body)
		if err != nil {
			return nil, err
		}
		body, err = ioutil.ReadAll(reader)
	} else {
		body, err = ioutil.ReadAll(r.resp.Body)
	}

	return
}

// FromJSON 解析请求结果JSON到v
func (r *Response) FromJSON(v interface{}) error {
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
