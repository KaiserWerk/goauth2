package storage

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type Scope []string

func (s *Scope) MarshalJSON() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("scope is nil")
	}
	return []byte(fmt.Sprintf("%q", url.QueryEscape(strings.Join(*s, " ")))), nil
}

func (s *Scope) UnmarshalJSON(d []byte) error {
	elems := make([]string, 0, 5)
	err := json.Unmarshal(d, &elems)
	if err != nil {
		return err
	}

	*s = elems

	return nil
}

func (s *Scope) String() string {
	return url.QueryEscape(strings.Join(*s, " "))
}
