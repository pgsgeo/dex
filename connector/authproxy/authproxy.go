// Package authproxy implements a connector which relies on external
// authentication (e.g. mod_auth in Apache2) and returns an identity with the
// HTTP header X-Remote-User as verified email.
package authproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds the configuration parameters for a connector which returns an
// identity with the HTTP header X-Remote-User as verified email,
// X-Remote-Group and configured staticGroups as user's group.
// Headers retrieved to fetch user's email and group can be configured
// with userHeader and groupHeader.
type Config struct {
	UserHeader          string   `json:"userHeader"`
	GroupHeader         string   `json:"groupHeader"`
	NameHeader          string   `json:"nameHeader"`
	OrganizationsHeader string   `json:"organizationsHeader"`
	RelationsHeader     string   `json:"relationsHeader"`
	Groups              []string `json:"staticGroups"`
}

// Open returns an authentication strategy which requires no user interaction.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	userHeader := c.UserHeader
	if userHeader == "" {
		userHeader = "X-Remote-User"
	}
	groupHeader := c.GroupHeader
	if groupHeader == "" {
		groupHeader = "X-Remote-Group"
	}
	nameHeader := c.NameHeader
	if nameHeader == "" {
		nameHeader = "X-Remote-Name"
	}
	organizationsHeader := c.OrganizationsHeader
	if organizationsHeader == "" {
		organizationsHeader = "X-Remote-Organizations"
	}
	relationsHeader := c.RelationsHeader
	if relationsHeader == "" {
		relationsHeader = "X-Remote-Relations"
	}

	return &callback{userHeader: userHeader, groupHeader: groupHeader, organizationsHeader: organizationsHeader, relationsHeader: relationsHeader, nameHeader: nameHeader, logger: logger, pathSuffix: "/" + id, groups: c.Groups}, nil
}

// Callback is a connector which returns an identity with the HTTP header
// X-Remote-User as verified email.
type callback struct {
	userHeader          string
	groupHeader         string
	nameHeader          string
	organizationsHeader string
	relationsHeader     string
	groups              []string
	logger              log.Logger
	pathSuffix          string
}

// LoginURL returns the URL to redirect the user to login with.
func (m *callback) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	u.Path += m.pathSuffix
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

// HandleCallback parses the request and returns the user's identity
func (m *callback) HandleCallback(s connector.Scopes, r *http.Request) (connector.Identity, error) {
	remoteUser := r.Header.Get(m.userHeader)
	if remoteUser == "" {
		return connector.Identity{}, fmt.Errorf("required HTTP header %s is not set", m.userHeader)
	}
	groups := m.groups
	headerGroup := r.Header.Get(m.groupHeader)
	if headerGroup != "" {
		splitheaderGroup := strings.Split(headerGroup, ",")
		for i, v := range splitheaderGroup {
			splitheaderGroup[i] = strings.TrimSpace(v)
		}
		groups = append(splitheaderGroup, groups...)
	}

	var remoteName map[string]string
	if name := r.Header.Get(m.nameHeader); name != "" {
		if err := json.Unmarshal([]byte(name), &remoteName); err != nil {
			return connector.Identity{}, fmt.Errorf("unmarshal name: %v", err)
		}
	}

	var remoteOrganizations []map[string]interface{}
	if orgs := r.Header.Get(m.organizationsHeader); orgs != "" {
		if err := json.Unmarshal([]byte(orgs), &remoteOrganizations); err != nil {
			return connector.Identity{}, fmt.Errorf("unmarshal organizations: %v", err)
		}
	}
	var remoteRelations []map[string]interface{}
	if relations := r.Header.Get(m.relationsHeader); relations != "" {
		if err := json.Unmarshal([]byte(relations), &remoteRelations); err != nil {
			return connector.Identity{}, fmt.Errorf("unmarshal relations: %v", err)
		}
	}

	return connector.Identity{
		UserID:        remoteUser, // TODO: figure out if this is a bad ID value.
		Email:         remoteUser,
		EmailVerified: true,
		Groups:        groups,

		Name: connector.Name{
			GivenName:  remoteName["givenName"],
			FamilyName: remoteName["familyName"],
			FullName:   remoteName["fullName"],
		},
		Organizations: remoteOrganizations,
		Relations:     remoteRelations,
	}, nil
}
