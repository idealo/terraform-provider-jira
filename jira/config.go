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

func (adt *CustomAuthHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add(adt.customAuthHeaderKey, adt.customAuthHeaderValue)
	return adt.Transport.RoundTrip(req)
}

func (c *Config) createAndAuthenticateClient(d *schema.ResourceData) error {
	log.Printf("[INFO] creating jira client using environment variables")

	customTransport := buildCustomHeader(d)

	isBasicAuth := d.Get("username") != nil && d.Get("password") != nil
	isPatAuth := d.Get("pat_token") != nil

	switch {
	case isBasicAuth:
		return createBasicAuthClient(d, customTransport, c)
	case isPatAuth:
		return createPatClient(d, customTransport, c)
	case isPatAuth && isBasicAuth:
		return errors.New("Only one client type allowed. Can not create two clients, BasicAuth or PAT Auth.")
	default:
		return errors.New("Could not create a JIRA client, either set 'username' and 'password' or 'pat_token'")
	}
}

func createBasicAuthClient(d *schema.ResourceData, customTransport CustomAuthHeaderTransport, c *Config) error {
	tp := jira.BasicAuthTransport{
		Username:  d.Get("username").(string),
		Password:  d.Get("password").(string),
		Transport: &customTransport,
	}

	return createClient(d, &tp, c)
}

func createPatClient(d *schema.ResourceData, customTransport CustomAuthHeaderTransport, c *Config) error {
	tp := jira.BearerAuthTransport{
		Token:     d.Get("pat_token").(string),
		Transport: &customTransport,
	}

	return createClient(d, &tp, c)
}

func createClient(d *schema.ResourceData, tp AuthTransport, c *Config) error {
	jiraClient, err := jira.NewClient(tp.Client(), d.Get("url").(string))
	if err != nil {
		return errors.Wrap(err, "creating jira client failed")
	}

	c.jiraClient = jiraClient
	return nil
}

func buildCustomHeader(d *schema.ResourceData) CustomAuthHeaderTransport {
	transport := CustomAuthHeaderTransport{}

	if d.Get("custom_auth_header_key") != nil && d.Get("custom_auth_header_value") != nil {
		transport = CustomAuthHeaderTransport{
			customAuthHeaderKey:   d.Get("custom_auth_header_key").(string),
			customAuthHeaderValue: d.Get("custom_auth_header_value").(string),
			Transport:             http.DefaultTransport,
		}
	}
	return transport
}
