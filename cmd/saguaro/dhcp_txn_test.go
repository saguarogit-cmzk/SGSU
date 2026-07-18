package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// fakeKeaAgent is a stateful control-agent stub for the subnet transaction:
// it stores the "running config" and can be told to fail config-test or
// status-get to exercise validation aborts and the rollback path.
type fakeKeaAgent struct {
	mu         sync.Mutex
	cfg        map[string]any
	failTest   bool
	failStatus bool
	writes     int
	sets       [][]byte
}

func newFakeKeaAgent(t *testing.T) (*fakeKeaAgent, *httptest.Server) {
	t.Helper()
	f := &fakeKeaAgent{}
	_ = json.Unmarshal([]byte(`{"Dhcp4":{"subnet4":[{"id":1,"subnet":"192.168.10.0/24","pools":[{"pool":"192.168.10.100 - 192.168.10.200"}]}],"valid-lifetime":3600}}`), &f.cfg)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command   string          `json:"command"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		switch req.Command {
		case "config-get":
			b, _ := json.Marshal(f.cfg)
			w.Write([]byte(`[{"result":0,"arguments":` + string(b) + `}]`))
		case "config-test":
			if f.failTest {
				w.Write([]byte(`[{"result":1,"text":"syntax error in simulated test"}]`))
				return
			}
			w.Write([]byte(`[{"result":0}]`))
		case "config-set":
			var cfg map[string]any
			if err := json.Unmarshal(req.Arguments, &cfg); err != nil {
				w.Write([]byte(`[{"result":1,"text":"bad arguments"}]`))
				return
			}
			f.cfg = cfg
			f.sets = append(f.sets, append([]byte(nil), req.Arguments...))
			w.Write([]byte(`[{"result":0}]`))
		case "status-get":
			if f.failStatus {
				w.Write([]byte(`[{"result":1,"text":"simulated crash"}]`))
				return
			}
			w.Write([]byte(`[{"result":0,"arguments":{"pid":1}}]`))
		case "config-write":
			f.writes++
			w.Write([]byte(`[{"result":0}]`))
		default:
			w.Write([]byte(`[{"result":2,"text":"unknown"}]`))
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeKeaAgent) subnetCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.cfg["Dhcp4"].(map[string]any)
	list, _ := d["subnet4"].([]any)
	return len(list)
}

func TestSubnetTransactionLifecycle(t *testing.T) {
	fake, agent := newFakeKeaAgent(t)
	srv, c, a := newTestServer(t)
	a.keaURL, a.keaUser, a.keaPass = agent.URL, "u", "p"
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"subnet":"192.168.20.0/24","poolStart":"192.168.20.100","poolEnd":"192.168.20.200","router":"192.168.20.1","domain":"lan","dnsServers":["192.168.20.1"]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/dhcp/subnets", body); r.StatusCode != http.StatusOK {
		t.Fatalf("subnet add: got %d", r.StatusCode)
	}
	if fake.subnetCount() != 2 || fake.writes != 1 {
		t.Fatalf("after add: subnets=%d writes=%d", fake.subnetCount(), fake.writes)
	}
	// Update pool of subnet 2.
	upd := `{"subnet":"192.168.20.0/24","poolStart":"192.168.20.50","poolEnd":"192.168.20.99","router":"","domain":"","dnsServers":[]}`
	if r := reqJSON(t, srv, c, http.MethodPut, "/api/dhcp/subnets/2", upd); r.StatusCode != http.StatusOK {
		t.Fatalf("subnet update: got %d", r.StatusCode)
	}
	// Delete subnet 2.
	if r := reqJSON(t, srv, c, http.MethodDelete, "/api/dhcp/subnets/2", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("subnet delete: got %d", r.StatusCode)
	}
	if fake.subnetCount() != 1 {
		t.Fatalf("after delete: subnets=%d", fake.subnetCount())
	}
}

func TestSubnetTransactionValidationAbort(t *testing.T) {
	fake, agent := newFakeKeaAgent(t)
	fake.failTest = true
	srv, c, a := newTestServer(t)
	a.keaURL, a.keaUser, a.keaPass = agent.URL, "u", "p"
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"subnet":"192.168.20.0/24","poolStart":"192.168.20.100","poolEnd":"192.168.20.200","router":"","domain":"","dnsServers":[]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/dhcp/subnets", body); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("failing config-test: got %d, want 400", r.StatusCode)
	}
	if len(fake.sets) != 0 || fake.subnetCount() != 1 {
		t.Fatalf("config-set must not run when validation fails: sets=%d subnets=%d", len(fake.sets), fake.subnetCount())
	}
}

func TestSubnetTransactionRollbackOnVerifyFailure(t *testing.T) {
	fake, agent := newFakeKeaAgent(t)
	fake.failStatus = true
	srv, c, a := newTestServer(t)
	a.keaURL, a.keaUser, a.keaPass = agent.URL, "u", "p"
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"subnet":"192.168.20.0/24","poolStart":"192.168.20.100","poolEnd":"192.168.20.200","router":"","domain":"","dnsServers":[]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/dhcp/subnets", body); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("failing verify: got %d, want 400", r.StatusCode)
	}
	// Two config-set calls: the apply and the rollback; state must be back to
	// the original single subnet and nothing persisted.
	if len(fake.sets) != 2 || fake.subnetCount() != 1 || fake.writes != 0 {
		t.Fatalf("rollback wrong: sets=%d subnets=%d writes=%d", len(fake.sets), fake.subnetCount(), fake.writes)
	}
}
