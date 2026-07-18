// Package kea is the DHCP adapter: runtime state (status, subnets, leases)
// comes from the Kea control agent on 127.0.0.1:8000 with basic auth, and
// host reservations are managed directly in Kea's PostgreSQL hosts table —
// Kea reads that backend on demand, no premium hooks required.
package kea

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	URL      string
	Username string
	Password string
	HTTP     *http.Client
}

func New(url, username, password string) *Client {
	return &Client{URL: url, Username: username, Password: password,
		HTTP: &http.Client{Timeout: 10 * time.Second}}
}

type answer struct {
	Result    int             `json:"result"`
	Text      string          `json:"text"`
	Arguments json.RawMessage `json:"arguments"`
}

// Call sends one command to the dhcp4 service through the control agent and
// returns the answer's arguments.
func (c *Client) Call(ctx context.Context, command string, args any) (json.RawMessage, error) {
	payload := map[string]any{"command": command, "service": []string{"dhcp4"}}
	if args != nil {
		payload["arguments"] = args
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.Username, c.Password)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("kea control agent rejected credentials")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kea control agent: HTTP %d", resp.StatusCode)
	}
	var answers []answer
	if err := json.NewDecoder(resp.Body).Decode(&answers); err != nil {
		return nil, fmt.Errorf("unparseable control agent response: %w", err)
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("empty control agent response")
	}
	// result 3 = command succeeded with empty content (e.g. no leases).
	if answers[0].Result != 0 && answers[0].Result != 3 {
		return nil, fmt.Errorf("kea %s: %s", command, answers[0].Text)
	}
	return answers[0].Arguments, nil
}

type Subnet struct {
	ID     int64    `json:"id"`
	Subnet string   `json:"subnet"`
	Pools  []string `json:"pools"`
}

// Subnets reads the running configuration and extracts subnet4.
func (c *Client) Subnets(ctx context.Context) ([]Subnet, error) {
	raw, err := c.Call(ctx, "config-get", nil)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Dhcp4 struct {
			Subnet4 []struct {
				ID     int64  `json:"id"`
				Subnet string `json:"subnet"`
				Pools  []struct {
					Pool string `json:"pool"`
				} `json:"pools"`
			} `json:"subnet4"`
		} `json:"Dhcp4"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	out := make([]Subnet, 0, len(cfg.Dhcp4.Subnet4))
	for _, s := range cfg.Dhcp4.Subnet4 {
		sub := Subnet{ID: s.ID, Subnet: s.Subnet}
		for _, p := range s.Pools {
			sub.Pools = append(sub.Pools, p.Pool)
		}
		out = append(out, sub)
	}
	return out, nil
}

type Lease struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	SubnetID int64  `json:"subnetId"`
	State    int    `json:"state"`
	Expires  int64  `json:"expires"` // unix seconds (cltt + valid-lft)
}

// Leases lists all DHCPv4 leases via the lease_cmds hook.
func (c *Client) Leases(ctx context.Context) ([]Lease, error) {
	raw, err := c.Call(ctx, "lease4-get-all", nil)
	if err != nil {
		return nil, err
	}
	var args struct {
		Leases []struct {
			IP       string `json:"ip-address"`
			HW       string `json:"hw-address"`
			Hostname string `json:"hostname"`
			SubnetID int64  `json:"subnet-id"`
			State    int    `json:"state"`
			CLTT     int64  `json:"cltt"`
			ValidLft int64  `json:"valid-lft"`
		} `json:"leases"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, err
		}
	}
	out := make([]Lease, 0, len(args.Leases))
	for _, l := range args.Leases {
		out = append(out, Lease{IP: l.IP, MAC: l.HW, Hostname: l.Hostname,
			SubnetID: l.SubnetID, State: l.State, Expires: l.CLTT + l.ValidLft})
	}
	return out, nil
}

// Status returns the raw status-get arguments (pid, uptime, state).
func (c *Client) Status(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, "status-get", nil)
}
