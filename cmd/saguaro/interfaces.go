package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	// SysName is the name the kernel would have given this port on its own
	// (enp2s0). Once the port map renames ports to lan0/wan1/net1, that name is
	// the only cue left tying a row to a physical socket on the chassis.
	SysName string `json:"sysName"`
	// Bus is the PCI/USB address of the port (0000:02:00.0), which is what the
	// kernel name encodes and what survives when nothing else does.
	Bus   string `json:"bus"`
	Role  string `json:"role"`  // WAN | LAN | mgmt | ""
	Label string `json:"label"` // operator-friendly alias (e.g. "WAN1", "LAN")
}

var nicNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)
var nicLabelRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{0,24}$`)

func (a *app) getNICLabels() map[string]string {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	out := map[string]string{}
	for k, v := range a.store.data.NICLabels {
		out[k] = v
	}
	return out
}

func (a *app) setNICLabel(name, label string) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if a.store.data.NICLabels == nil {
		a.store.data.NICLabels = map[string]string{}
	}
	if label == "" {
		delete(a.store.data.NICLabels, name)
	} else {
		a.store.data.NICLabels[name] = label
	}
	return a.store.saveLocked()
}

// migrateNICLabels moves aliases that are still keyed on a port's old kernel
// name onto the logical name the port map gave it. Without this, renaming the
// ports silently orphans every alias the operator wrote before the migration --
// they stay in the store, attached to interfaces that no longer exist. An alias
// already set on the new name wins, since the operator wrote it more recently.
func (a *app) migrateNICLabels(nics []nicInfo) {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	labels := a.store.data.NICLabels
	if len(labels) == 0 {
		return
	}
	changed := false
	for _, n := range nics {
		if n.SysName == "" || n.SysName == n.Name {
			continue
		}
		old, ok := labels[n.SysName]
		if !ok {
			continue
		}
		if _, taken := labels[n.Name]; !taken {
			labels[n.Name] = old
		}
		delete(labels, n.SysName)
		changed = true
	}
	if changed {
		_ = a.store.saveLocked()
	}
}

// apiInterfaceLabel sets (or clears) an interface's friendly alias.
func (a *app) apiInterfaceLabel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !nicNameRe.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid interface name")
		return
	}
	var in struct {
		Label string `json:"label"`
	}
	if err := decodeJSONOptional(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	in.Label = strings.TrimSpace(in.Label)
	if !nicLabelRe.MatchString(in.Label) {
		writeError(w, http.StatusBadRequest, "label may be up to 24 chars (letters, digits, space . _ -)")
		return
	}
	if err := a.setNICLabel(name, in.Label); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist interface label")
		return
	}
	a.record(r, a.actor(r), "nic-label", name, "success", map[string]any{"label": in.Label})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name, "label": in.Label})
}

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
		if link, err := os.Readlink("/sys/class/net/" + name + "/device"); err == nil {
			parts := strings.Split(link, "/")
			n.Bus = parts[len(parts)-1]
		}
		n.SysName = udevName(ctx2, name)
		if n.Addresses == nil {
			n.Addresses = []string{}
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// udevName returns the predictable name udev derived for this port
// (ID_NET_NAME_ONBOARD, then _SLOT, then _PATH), which is what the interface
// would be called had the port map not renamed it. Empty when udev has nothing
// to say -- a virtual device, or a system without a udev database.
func udevName(ctx context.Context, name string) string {
	out, err := exec.CommandContext(ctx, "udevadm", "info", "-q", "property", "-p", "/sys/class/net/"+name).Output()
	if err != nil {
		return ""
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	for _, key := range []string{"ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH"} {
		if v := props[key]; v != "" && nicNameRe.MatchString(v) {
			return v
		}
	}
	return ""
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
	a.migrateNICLabels(nics)
	labels := a.getNICLabels()
	for i := range nics {
		nics[i].Role = a.nicRole(nics[i].Name)
		nics[i].Label = labels[nics[i].Name]
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
	if err := decodeJSONOptional(w, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
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
// The body is capped at 1 MiB (like decodeJSON) and a malformed non-empty body
// is a real error the caller must reject, rather than being silently treated as
// an empty object (which would apply zero values).
func decodeJSONOptional(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}
