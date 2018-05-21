package okta

import (
	"fmt"
)

type OAuthClientsService service

type OAuthClient struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientIDIssuedAt        float64  `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   float64  `json:"client_secret_expires_at,omitempty"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	LogoURI                 string   `json:"logo_uri"`
	ApplicationType         string   `json:"application_type"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	ResponseTypes           []string `json:"response_types"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	InitiateLoginURI        string   `json:"initiate_login_uri"`
	TOSURI                  string   `json:"tos_uri"`
	PolicyURI               string   `json:"policy_uri"`
}

func (c OAuthClient) String() string {
	return fmt.Sprintf("OAuthClient:(ID: {%v} - Name: {%v})", c.ClientID, c.ClientName)
}

func (c *OAuthClientsService) Create(newClient OAuthClient) (*OAuthClient, *Response, error) {
	u := "clients"
	req, err := c.client.NewRequest("POST", u, newClient)
	if err != nil {
		return nil, nil, err
	}

	//buf, _ := json.MarshalIndent(newClient, "", "  ")
	//fmt.Printf("Create OAuth Client with this data: %s\n", buf)

	createdClient := new(OAuthClient)
	resp, err := c.client.Do(req, createdClient)
	if err != nil {
		return nil, resp, err
	}

	// buf, _ := json.MarshalIndent(createdClient, "", "  ")
	// fmt.Printf("Created OAuth Client: %s\n", buf)

	return createdClient, resp, nil
}

func (c *OAuthClientsService) Delete(clientId string) (*Response, error) {
	u := fmt.Sprintf("clients/%s", clientId)

	req, err := c.client.NewRequest("DELETE", u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req, nil)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

type ClientListFilterOptions struct {
	Q     *string
	Limit uint32
	after *string
}

type clientListURLFilterOptions struct {
	Q     string `url:"q,omitempty"`
	Limit uint32 `url:"limit,omitempty"`
	After string `url:"after,omitempty"`
}

func NewClientListFilterOptions(appname string, limit uint32) *ClientListFilterOptions {
	return &ClientListFilterOptions{
		Q:     &appname,
		Limit: limit,
		after: nil,
	}
}

func (c *OAuthClientsService) List(next string) ([]OAuthClient, string, *Response, error) {
	q := ""
	var after *string
	if next == "" {
		after = nil
	} else {
		after = &next
	}
	opt := ClientListFilterOptions{
		Q:     &q,
		Limit: 0,
		after: after,
	}

	clients, resp, err := c.ListWithFilter(&opt)
	return clients, *opt.after, resp, err
}

func (c *OAuthClientsService) ListWithFilter(opt *ClientListFilterOptions) ([]OAuthClient, *Response, error) {
	urlOpts := clientListURLFilterOptions{"", 0, ""}
	if opt.after != nil {
		urlOpts.After = *opt.after
	} else if opt.Q != nil {
		urlOpts.Q = *opt.Q
	}

	if opt.Limit == 0 {
		urlOpts.Limit = defaultLimit
	} else {
		urlOpts.Limit = opt.Limit
	}

	u, err := addOptions("clients", urlOpts)
	if err != nil {
		return nil, nil, err
	}

	req, err := c.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	clients := make([]OAuthClient, 1)
	resp, err := c.client.Do(req, &clients)
	if err != nil {
		return nil, resp, err
	}

	if resp.NextURL != nil {
		a := resp.NextURL.Query().Get("after")
		opt.after = &a
	} else {
		opt.after = nil
	}

	return clients, resp, nil
}

func (c *OAuthClientsService) GetByID(clientId string) (*OAuthClient, *Response, error) {
	u := fmt.Sprintf("clients/%v", clientId)
	req, err := c.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	client := new(OAuthClient)
	resp, err := c.client.Do(req, client)
	if err != nil {
		return nil, resp, err
	}

	return client, resp, nil
}
