package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type nicInfo struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	State     string   `json:"state"`
	Carrier   bool     `json:"carrier"`
	SpeedMb   int      `json:"speedMb"`
	Driver    string   `json:"driver"`
	Addresses []string `json:"addresses"`
	Role      string   `json:"role"` // WAN | LAN | mgmt | ""
}

var nicNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

func defaultRunNet(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	full := append([]string{"-n", "/usr/sbin/saguaro-net"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

func sysRead(name, file string) string {
	b, err := os.ReadFile("/sys/class/net/" + name + "/" + file)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// defaultReadInterfaces enumerates NICs from /sys and their addresses from
// `ip -json addr`. Returns an empty list off-Linux (development on Windows).
func defaultReadInterfaces(ctx context.Context) ([]nicInfo, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return []nicInfo{}, nil
	}
	addrs := map[string][]string{}
	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx2, "ip", "-json", "addr", "show").Output(); err == nil {
		var raw []struct {
			Ifname   string `json:"ifname"`
			AddrInfo []struct {
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
				Family    string `json:"family"`
			} `json:"addr_info"`
		}
		if json.Unmarshal(out, &raw) == nil {
			for _, r := range raw {
				for _, ai := range r.AddrInfo {
					if ai.Family == "inet" {
						addrs[r.Ifname] = append(addrs[r.Ifname], ai.Local+"/"+strconv.Itoa(ai.Prefixlen))
					}
				}
			}
		}
	}
	var out []nicInfo
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		n := nicInfo{
			Name:      name,
			MAC:       sysRead(name, "address"),
			State:     sysRead(name, "operstate"),
			Carrier:   sysRead(name, "carrier") == "1",
			Addresses: addrs[name],
		}
		if sp := sysRead(name, "speed"); sp != "" {
			if v, err := strconv.Atoi(sp); err == nil && v > 0 {
				n.SpeedMb = v
			}
		}
		if link, err := os.Readlink("/sys/class/net/" + name + "/device/driver"); err == nil {
			parts := strings.Split(link, "/")
			n.Driver = parts[len(parts)-1]
		}
		if n.Addresses == nil {
			n.Addresses = []string{}
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (a *app) nicRole(name string) string {
	if gw, ok := a.getGateway(); ok && gw.GatewayEnabled {
		switch name {
		case gw.WANInterface:
			return "WAN"
		case gw.LANInterface:
			return "LAN"
		}
	}
	return ""
}

func (a *app) apiInterfacesList(w http.ResponseWriter, r *http.Request) {
	nics, err := a.readInterfaces(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read interfaces")
		return
	}
	for i := range nics {
		nics[i].Role = a.nicRole(nics[i].Name)
	}
	if nics == nil {
		nics = []nicInfo{}
	}
	writeJSON(w, http.StatusOK, nics)
}

func (a *app) apiInterfaceIdentify(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nicNameRe.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid interface name")
		return
	}
	var in struct {
		Seconds int `json:"seconds"`
	}
	_ = decodeJSONOptional(r, &in)
	secs := in.Seconds
	if secs < 1 || secs > 30 {
		secs = 10
	}
	if out, err := a.runNet(r.Context(), "identify", name, strconv.Itoa(secs)); err != nil {
		writeError(w, http.StatusBadGateway, "identify failed: "+truncate(string(out), 200))
		return
	}
	a.record(r, a.actor(r), "nic-identify", name, "success", map[string]any{"seconds": secs})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "seconds": secs,
		"message": "port LED blinking for " + strconv.Itoa(secs) + "s"})
}

// decodeJSONOptional decodes a body if present; an empty body is not an error.
func decodeJSONOptional(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}
