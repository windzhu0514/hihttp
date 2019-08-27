package hihttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
)

func ExampleGet() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello,hihttp"))
	}))
	defer srv.Close()

	code, data, err := Get(srv.URL)
	fmt.Println(code, string(data), err)

	// Output:
	// 200 hello,hihttp <nil>
}

func ExamplePost() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("hi", r.FormValue("hi"))
		fmt.Println("go", r.FormValue("go"))
		fmt.Println("http", r.FormValue("http"))
	}))
	defer srv.Close()

	postData := url.Values{}
	postData.Add("hi", "everyone")
	postData.Add("go", "is a good language")
	postData.Add("hihttp", "is a good package")
	code, data, err := Post(srv.URL, MIMEPOSTForm, postData.Encode())
	fmt.Println(code, string(data), err)

	// Output:
	// hi everyone
	// go is a good language
	// hihttp is a good package
	// 200  <nil>
}

func ExampleProxy() {
	SetProxy("socks5://127.0.0.1:1080")
	// SetProxy("http://127.0.0.1:1080")
	// SetProxy("https://127.0.0.1:1080")
	// SetAuthProxy("socks5://127.0.0.1:1080", "proxyUserName", "proxyPassword")
	// SetAuthProxy("http://127.0.0.1:1080", "proxyUserName", "proxyPassword")
	// SetAuthProxy("https://127.0.0.1:1080", "proxyUserName", "proxyPassword")

	statusCode, _, err := Get("https://www.google.com")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(statusCode, err)

	// Output:
	// 200  <nil>
}
