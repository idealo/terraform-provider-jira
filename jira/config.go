package jira

import (
	"log"
	"net/http"

	jira "github.com/andygrunwald/go-jira"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

type Config struct {
	jiraClient *jira.Client
}

type AuthTransport interface {
	Client() *http.Client
}

type CustomAuthHeaderTransport struct {
	customAuthHeaderKey   string
	customAuthHeaderValue string
	Transport             http.RoundTripper
}

func (adt CustomAuthHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add(adt.customAuthHeaderKey, adt.customAuthHeaderValue)
	return adt.Transport.RoundTrip(req)
}

func (c *Config) createAndAuthenticateClient(d *schema.ResourceData) error {
	log.Printf("[INFO] creating jira client using environment variables")

	transport, err := buildTransport(d)
	if err != nil {
		return err
	}
	jiraUsername, jiraUsernameSet := d.GetOk("user")
	jiraPassword, jiraPasswordSet := d.GetOk("password")
	isBasicAuth := jiraUsernameSet && jiraPasswordSet
	patToken, isPatAuth := d.GetOk("pat_token")
	jiraURL := d.Get("url").(string)

	switch {
	case isBasicAuth:
		return createBasicAuthClient(jiraUsername.(string), jiraPassword.(string), jiraURL, transport, c)
	case isPatAuth:
		return createPatClient(patToken.(string), jiraURL, transport, c)
	case isPatAuth && isBasicAuth:
		return errors.New("Only one client type allowed. Can not create two clients, BasicAuth or PAT Auth.")
	default:
		return errors.New("Could not create a JIRA client, either set 'username' and 'password' or 'pat_token'")
	}
}

func createBasicAuthClient(username string, password string, URL string, customTransport http.RoundTripper, c *Config) error {
	tp := jira.BasicAuthTransport{
		Username:  username,
		Password:  password,
		Transport: customTransport,
	}

	return createClient(URL, &tp, c)
}

func createPatClient(patToken string, URL string, customTransport http.RoundTripper, c *Config) error {
	tp := jira.BearerAuthTransport{
		Token:     patToken,
		Transport: customTransport,
	}
	return createClient(URL, &tp, c)
}

func createClient(URL string, tp AuthTransport, c *Config) error {
	jiraClient, err := jira.NewClient(tp.Client(), URL)
	if err != nil {
		return errors.Wrap(err, "creating jira client failed")
	}

	c.jiraClient = jiraClient
	return nil
}

func buildTransport(d *schema.ResourceData) (http.RoundTripper, error) {
	customAuthHeaderKey, customAuthHeaderKeySet := d.GetOk("custom_auth_header_key")
	customAuthHeaderValue, customAuthHeaderValueSet := d.GetOk("custom_auth_header_value")
	if customAuthHeaderKeySet && customAuthHeaderValueSet {
		transport := CustomAuthHeaderTransport{
			customAuthHeaderKey:   customAuthHeaderKey.(string),
			customAuthHeaderValue: customAuthHeaderValue.(string),
			Transport:             http.DefaultTransport,
		}
		return transport, nil
	}
	if (!customAuthHeaderKeySet) && (!customAuthHeaderValueSet) {
		return http.DefaultTransport, nil
	}
	return nil, errors.New("custom_auth_header_key and custom_auth_header_value must be set together ")
}
