package intitools

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	//"github.com/pquerna/otp/totp"
	"golang.org/x/net/html"
	"golang.org/x/time/rate"
)

const (
	ApiURL   = "https://api.intigriti.com"
	AppURL   = "https://app.intigriti.com"
	LoginURL = "https://login.intigriti.com"
	SiteURL =  "https://www.intigriti.com"
)

type Client struct {
	ApiURL        string
	AppURL        string
	LoginURL      string
	SiteURL      string
	apiKey        string
	Authenticated bool
	username      string
	password      string
	secret        string
	LastViewed    int64
	WebhookURL    string
	Ratelimiter   *rate.Limiter
	HTTPClient    *http.Client
}

type ResponseState struct {
	Status              int    `json:"status"`
	Closereason         int    `json:"closeReason"`
	Duplicatesubmission string `json:"duplicateSubmission"`
}

type ResponsePayout struct {
	Value    float32 `json:"value"`
	Currency string  `json:"currency"`
}

type ResponseUser struct {
	Role     string `json:"role"`
	Email    string `json:"email"`
	Userid   string `json:"userId"`
	Avatarid string `json:"avatarId"`
	Username string `json:"userName"`
}

func NewClient(username string, password string, secret string, rl *rate.Limiter) *Client {

    proxyURL, err := url.Parse("http://localhost:8080")

	if err != nil { panic(err)}

    //Cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}

	// To prevent long activity list on first execution, limit them to last hour
	lastVisited := time.Now().Unix()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        Proxy: http.ProxyURL(proxyURL),
	}
	return &Client{
		ApiURL:     ApiURL,
		LoginURL:   LoginURL,
		AppURL:     AppURL,
		apiKey:     "",
		username:   username,
		password:   password,
		secret:     secret,
		LastViewed: lastVisited,
		HTTPClient: &http.Client{
			Timeout:   time.Minute,
			Jar:       jar,
			Transport: tr,
		},
		Authenticated: false,
		Ratelimiter:   rl,
	}
}

func (c *Client) Authenticate() error {

	// 0 request to get cookieso
	req0, err := http.NewRequest("GET", "https://www.intigriti.com", nil)
	if err != nil {
		return err
	}

	res0, err := c.HTTPClient.Do(req0)
	if err != nil {
		return err
	}

	defer res0.Body.Close()

    log.Println("Req0 statuscode", res0.StatusCode)
	if res0.StatusCode < http.StatusOK || res0.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("unknown error, status code: %d", res0.StatusCode)
	}
	// First request to get login page (and CSRF token / cookies)
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/auth/dashboard", c.AppURL), nil)
	if err != nil {
		return err
	}

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

    log.Println("Req1 statuscode", res.StatusCode)
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("unknown error, status code: %d", res.StatusCode)
	}

	finalURL := res.Request.URL.String()

	// If last redirect was to /researcher/ we are already logged in (just grab API token)
	if finalURL[len(finalURL)-12:] != "/researcher/" {
		// Parse HTML and find CSRF token and Return URL
		root, err := html.Parse(res.Body)
		if err != nil {
			return fmt.Errorf("unknown error 1, status code: %d", res.StatusCode)
		}

		csrfToken, err := c.getElementValue("__RequestVerificationToken", root)
		log.Println("csrf", csrfToken)
		if err != nil {
			log.Fatal(err.Error())
		}

		returnURL, err := c.getElementValue("Input.ReturnUrl", root)
		if err != nil {
			log.Fatal(err.Error())
		}

		// Prepare form for POST request
        // This POST Request only requieres the username  
		form := url.Values{}
		form.Add("__RequestVerificationToken", csrfToken)
		form.Add("Input.ReturnUrl", returnURL)
        //log.Println("returnURL", returnURL)
		form.Add("Input.Email", c.username)
        form.Add("Input.RememberLogin", "true")
        form.Add("Input.LocalLogin", "false")
        form.Add("Input.WebHostUrl", "https://app.intigriti.com")
        //log.Println("Input.Email", c.username)
		//form.Add("Input.Password", c.password)
        //log.Println("Input.Password", c.password)

		// We do not expect response body. Cookie is all we need (handled by CookieJar)
		req2, err := http.NewRequest("POST", fmt.Sprintf("%s/Account/Login?returnUrl=%s", c.LoginURL, url.QueryEscape(returnURL)), strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res2, err := c.HTTPClient.Do(req2)
		if err != nil {
			return err
		}

		defer res2.Body.Close()
        log.Println("request2 POST")
        //bodyBytes, err := io.ReadAll(res2.Body)
        if err != nil {    log.Fatal(err)       }
        //bodyString := string(bodyBytes)
            //log.Println(bodyString)

		// Check status
		if res2.StatusCode < http.StatusOK || res2.StatusCode >= http.StatusBadRequest {
			return fmt.Errorf("unknown error 2, status code: %d", res2.StatusCode)
		}

        //2nd POST with username and password
        form2 := url.Values{}
        form2.Add("__RequestVerificationToken", csrfToken)
        form2.Add("Input.ReturnUrl", returnURL)
        //log.Println("returnURL", returnURL)
        form2.Add("Input.Email", c.username)
        form2.Add("Input.RememberLogin", "True")
        form2.Add("Input.LocalLogin", "True")
        form2.Add("Input.WebHostUrl", "https%3A%2F%2Fapp.intigriti.com")
        form2.Add("Input.Password", c.password)
		//log.Println(c.password)
        req21, err := http.NewRequest("POST", fmt.Sprintf("%s/Account/Login?returnUrl=%s", c.LoginURL, url.QueryEscape(returnURL)), strings.NewReader(form2.Encode()))
        if err != nil {
            return err
        }
        req21.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        res21, err := c.HTTPClient.Do(req21)
        if err != nil {
            return err
        }

        defer res21.Body.Close()

		finalURL := res21.Request.URL.String()
        log.Println("finalURL", finalURL)
		// If last redirect was to /account/loginwith2fa we need a 2FA token
		if strings.Contains(finalURL, "/account/loginwith2fa") {
			if c.secret == "" {
				return fmt.Errorf("2FA is enabled but no secret is provided.")
			}

			// Parse HTML and find CSRF token and Return URL
			root, err := html.Parse(res2.Body)
			if err != nil {
				return fmt.Errorf("unknown error 3, status code: %d", res2.StatusCode)
			}

			csrfToken, err := c.getElementValue("__RequestVerificationToken", root)
			if err != nil {
				log.Fatal(err.Error())
			}

			//otpKey, err := totp.GenerateCode(c.secret, time.Now())
			//if err != nil {
			//	return err
			//}

			// Prepare OTP form for POST request
			otpForm := url.Values{}
			otpForm.Add("__RequestVerificationToken", csrfToken)
			//otpForm.Add("Input.TwoFactorAuthentication.VerificationCode", otpKey)

			req3, err := http.NewRequest("POST", finalURL, strings.NewReader(otpForm.Encode()))
			if err != nil {
				return err
			}

			req3.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			res3, err := c.HTTPClient.Do(req3)
			if err != nil {
				return err
			}

			defer res3.Body.Close()

            log.Println("res3 status", res3.StatusCode)
			// Check status
			if res3.StatusCode < http.StatusOK || res3.StatusCode >= http.StatusBadRequest {
				return fmt.Errorf("Unknown error 4, status code: %d", res3.StatusCode)
			}

			finalURL := res3.Request.URL.String()

			// If last redirect was not to /researcher/ the 2FA secret failed to authenticate
			if finalURL[len(finalURL)-12:] != "/researcher/" {
				return fmt.Errorf("Failed to authenticate with 2FA")
			}
		}

		//log.Println("Client authenticated!")
	}

	// Third request to get API token
	req4, err := http.NewRequest("GET", fmt.Sprintf("%s/auth/token", c.AppURL), nil)
	if err != nil {
		return err
	}

	res4, err := c.HTTPClient.Do(req4)
	if err != nil {
		return err
	}

	defer res4.Body.Close()

    log.Println("res4 code",res4.StatusCode)
	if res4.StatusCode < http.StatusOK || res4.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("unknown error 5, status code: %d", res4.StatusCode)
	}

	// Parse response to get API Token
	apiToken, err := ioutil.ReadAll(res4.Body)
	if err != nil {
		log.Fatal(err)
	}
	c.apiKey = string(apiToken[1 : len(apiToken)-1])
	c.Authenticated = true

	return nil
}

func (c *Client) sendRequest(req *http.Request, v interface{}) error {

	if !c.Authenticated {
		c.Authenticate()
	}
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("unknown error 5, status code: %d", res.StatusCode)
	}

	if err = json.NewDecoder(res.Body).Decode(&v); err != nil {
		return err
	}

	return nil
}
