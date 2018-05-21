package okta

import (
	"fmt"
	"time"
)

// AuthZSvcService handles communication with the Authorization Service
// data related methods of the OKTA API.
type AuthZSvcService service

type AuthZSvcLink struct {
	Href  string `json:"href"`
	Hints struct {
		Allow []string `json:"allow"`
	} `json:"hints"`
}

type AuthZSvcMetadataLink struct {
	AuthZSvcLink
	Name string `json:"name"`
}

type AuthZSvcLinks struct {
	Scopes     *AuthZSvcLink           `json:"scopes,omitempty"`
	Claims     *AuthZSvcLink           `json:"claims,omitempty"`
	Policies   *AuthZSvcLink           `json:"policies,omitempty"`
	Self       *AuthZSvcLink           `json:"self,omitempty"`
	MetaData   []*AuthZSvcMetadataLink `json:"metadata,omitempty"`
	RotateKey  *AuthZSvcLink           `json:"rotateKey,omitempty"`
	Deactivate *AuthZSvcLink           `json:"deactivate,omitempty"`
	Keys       *AuthZSvcLink           `json:"keys,omitempty"`
}

type AuthZSvcCredentials struct {
	KeyID        string     `json:"kid,omitempty"`
	LastRotated  *time.Time `json:"lastRotated,omitempty"`
	NextRotation *time.Time `json:"nextRotation,omitempty"`
	RotationMode string     `json:"rotationMode,omitempty"`
	Use          string     `json:"use,omitempty"`
}

type AuthZSvc struct {
	ID          string               `json:"id,omitempty"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Audiences   []string             `json:"audiences"`
	Issuer      string               `json:"issuer,omitempty"`
	IssuerMode  string               `json:"issuerMode,omitempty"`
	Status      string               `json:"status,omitempty"`
	Created     *time.Time           `json:"created,omitempty"`
	LastUpdate  *time.Time           `json:"lastUpdated,omitempty"`
	Credentials *AuthZSvcCredentials `json:"credentials,omitempty"`
	Links       *AuthZSvcLinks       `json:"_links,omitempty"`
}

func (a AuthZSvc) String() string {
	return fmt.Sprintf("AuthorizationService:(ID: {%v} - Name: {%v})", a.ID, a.Name)
}

func (a *AuthZSvcService) Create(authZSvcIn AuthZSvc) (*AuthZSvc, *Response, error) {
	u := "authorizationServers"

	req, err := a.client.NewRequest("POST", u, authZSvcIn)
	if err != nil {
		return nil, nil, err
	}

	//XXX
	// var stuff map[string]interface{}
	// body, _ := req.GetBody()
	// json.NewDecoder(body).Decode(&stuff)
	// buf, _ := json.MarshalIndent(stuff, "", "  ")
	// fmt.Printf("Create Authorization Service with this data: %s\n", buf)

	newAuthZSvc := new(AuthZSvc)
	resp, err := a.client.Do(req, newAuthZSvc)
	if err != nil {
		return nil, resp, err
	}

	//XXX
	// buf, _ = json.MarshalIndent(newAuthZSvc, "", "  ")
	// fmt.Printf("Created Authorization Service: %s\n", buf)

	return newAuthZSvc, resp, nil
}

func (a *AuthZSvcService) List() ([]AuthZSvc, *Response, error) {
	u := "authorizationServers"

	req, err := a.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	authZSvcs := make([]AuthZSvc, 1)
	resp, err := a.client.Do(req, &authZSvcs)
	if err != nil {
		return nil, resp, err
	}
	return authZSvcs, resp, nil
}

func (a *AuthZSvcService) Delete(authZSvcID string) (*Response, error) {
	u := fmt.Sprintf("authorizationServers/%v", authZSvcID)

	req, err := a.client.NewRequest("DELETE", u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req, nil)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

type AuthZSvcPolicyCondition struct {
	Clients struct {
		Include []string `json:"include,omitempty"`
		Exclude []string `json:"exclude,omitempty"`
	} `json:"clients"`
}

type AuthZSvcPolicyLinks struct {
	Self       *AuthZSvcLink `json:"self,omitempty"`
	Rules      *AuthZSvcLink `json:"rules,omitempty"`
	Deactivate *AuthZSvcLink `json:"deactivate,omitempty"`
}

type AuthZSvcPolicy struct {
	Type        string                   `json:"type"`
	ID          string                   `json:"id,omitempty"`
	Status      string                   `json:"status"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Priority    float64                  `json:"priority"`
	System      bool                     `json:"system"`
	Conditions  *AuthZSvcPolicyCondition `json:"conditions,omitempty"`
	Created     *time.Time               `json:"created,omitempty"`
	LastUpdated *time.Time               `json:"lastUpdated,omitempty"`
	Links       *AuthZSvcPolicyLinks     `json:"_links,omitempty"`
}

func NewAuthZSvcPolicy() AuthZSvcPolicy {
	return AuthZSvcPolicy{
		Type:       "OAUTH_AUTHORIZATION_POLICY",
		System:     false,
		Conditions: new(AuthZSvcPolicyCondition),
	}
}

func (a AuthZSvcPolicy) String() string {
	return fmt.Sprintf("AuthorizationServicePolicy:(ID: {%v} - Name: {%v})", a.ID, a.Name)
}

func (a *AuthZSvcService) CreatePolicy(authZSvcId string, authZSvcPolicyIn AuthZSvcPolicy) (*AuthZSvcPolicy, *Response, error) {
	u := fmt.Sprintf("authorizationServers/%v/policies", authZSvcId)

	req, err := a.client.NewRequest("POST", u, authZSvcPolicyIn)
	if err != nil {
		return nil, nil, err
	}

	//XXX
	// var stuff map[string]interface{}
	// body, _ := req.GetBody()
	// json.NewDecoder(body).Decode(&stuff)
	// buf, _ := json.MarshalIndent(stuff, "", "  ")
	// fmt.Printf("Create Policy with this data: %s\n", buf)

	newAuthZSvcPolicy := new(AuthZSvcPolicy)
	resp, err := a.client.Do(req, newAuthZSvcPolicy)
	if err != nil {
		return nil, resp, err
	}

	return newAuthZSvcPolicy, resp, nil
}

type AuthZSvcRuleCondition struct {
	People struct {
		Users struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
		} `json:"users"`
		Groups struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
		} `json:"groups"`
	} `json:"people"`
	GrantTypes struct {
		Include []string `json:"include"`
	} `json:"grantTypes"`
	Scopes struct {
		Include []string `json:"include"`
	} `json:"scopes"`
}

type AuthZSvcRuleAction struct {
	Token struct {
		AccessTokenLifetimeMinutes  float64 `json:"accessTokenLifetimeMinutes"`
		RefreshTokenLifetimeMinutes float64 `json:"refreshTokenLifetimeMinutes"`
		RefreshTokenWindow          float64 `json:"refreshTokenWindowMinutes"`
	} `json:"token"`
}

type AuthZSvcRuleLinks struct {
	Self       *AuthZSvcLink `json:"self,omitempty"`
	Deactivate *AuthZSvcLink `json:"deactivate,omitempty"`
}

type AuthZSvcRule struct {
	Type        string                 `json:"type"`
	ID          string                 `json:"id,omitempty"`
	Status      string                 `json:"status"`
	Name        string                 `json:"name"`
	Priority    float64                `json:priority`
	Created     *time.Time             `json:"created,omitempty"`
	LastUpdated *time.Time             `json:"lastUpdated,omitempty"`
	System      bool                   `json:"system"`
	Conditions  *AuthZSvcRuleCondition `json:"conditions,omitempty"`
	Actions     *AuthZSvcRuleAction    `json:"actions,omitempty"`
	Links       *AuthZSvcRuleLinks     `json:"_links,omitempty"`
}

func NewAuthZSvcRule() AuthZSvcRule {
	return AuthZSvcRule{
		Type:       "RESOURCE_ACCESS",
		System:     false,
		Conditions: new(AuthZSvcRuleCondition),
		Actions:    new(AuthZSvcRuleAction),
	}
}

func (a AuthZSvcRule) String() string {
	return fmt.Sprintf("AuthorizationServiceRule:(ID: {%v} - Name: {%v})", a.ID, a.Name)
}

func (a *AuthZSvcService) CreateRule(authZSvcId string, authZSvcPolicyId string, authZSvcRuleIn AuthZSvcRule) (*AuthZSvcRule, *Response, error) {
	u := fmt.Sprintf("authorizationServers/%v/policies/%v/rules", authZSvcId, authZSvcPolicyId)

	req, err := a.client.NewRequest("POST", u, authZSvcRuleIn)
	if err != nil {
		return nil, nil, err
	}

	newAuthZSvceRule := new(AuthZSvcRule)
	resp, err := a.client.Do(req, &newAuthZSvceRule)
	if err != nil {
		return nil, resp, err
	}

	return newAuthZSvceRule, resp, nil
}
