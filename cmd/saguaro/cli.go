package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"saguaro.local/network-manager/internal/adapters/portmap"
)

// runCLI handles the few things that must work before the control plane is
// running: the installer calls them while it is still assembling the appliance.
// It reports whether it recognised the command so main() can fall through to
// starting the server.
func runCLI(args []string) (int, bool) {
	switch args[0] {
	case "portmap":
		return cmdPortmap(args[1:]), true
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stderr, "usage: saguaro [portmap --lan NAME --wan NAME [--json|--plan]]\n\nWith no arguments the control plane starts normally.")
		return 0, true
	}
	return 0, false
}

// cmdPortmap prints the stable-port-name netplan for this machine's NICs, or
// the assignments as JSON with --json. Roles are derived from the interfaces the
// installer has already chosen, so a fresh install needs no extra questions.
func cmdPortmap(args []string) int {
	var lan, wan string
	asJSON, asPlan := false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--plan":
			asPlan = true
		case "--lan", "--wan":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "%s needs a value\n", args[i])
				return 2
			}
			if args[i] == "--lan" {
				lan = args[i+1]
			} else {
				wan = args[i+1]
			}
			i++
		case "--json":
			asJSON = true
		default:
			fmt.Fprintf(os.Stderr, "unknown argument %q\n", args[i])
			return 2
		}
	}
	ports, err := physicalPorts()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	as, err := portmap.Auto(ports, lan, wan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if asPlan {
		// "oldname newname" pairs, one per line, for the installer to feed to
		// `ip link set`. Only ports that still need renaming are listed.
		for _, a := range portmap.RenamePlan(as) {
			fmt.Printf("%s %s\n", a.Kernel, a.Name)
		}
		return 0
	}
	if asJSON {
		b, err := json.Marshal(as)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(string(b))
		return 0
	}
	out, err := portmap.GenerateNetplan(as)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Print(out)
	return 0
}

// physicalPorts lists real Ethernet ports: those with a backing device (which
// excludes lo, bridges, VLANs and tunnels) and a permanent MAC. Bonds and
// bridges must keep their kernel names -- renaming them would break the members
// they are built from.
func physicalPorts() ([]portmap.Port, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate interfaces: %w", err)
	}
	var out []portmap.Port
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		if _, err := os.Stat("/sys/class/net/" + name + "/device"); err != nil {
			continue
		}
		// ARPHRD_ETHER only; skip wireless, InfiniBand and friends.
		if strings.TrimSpace(sysRead(name, "type")) != "1" {
			continue
		}
		out = append(out, portmap.Port{Kernel: name, MAC: sysRead(name, "address")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kernel < out[j].Kernel })
	return out, nil
}

// revalidatingAssets makes browsers check with us before reusing a cached page
// asset. http.FileServer sets no ETag, no Last-Modified and no Cache-Control for
// files served out of an embed.FS, and with no validator at all a browser falls
// back to heuristic caching: it may keep serving an old app.js indefinitely
// without ever asking. On an appliance that updates itself in place that is a
// permanent trap -- the GUI silently runs old code against a new API, and the
// operator sees stale data with nothing to suggest a reload would help.
//
// "no-cache" does not mean "do not store": the asset stays cached, the browser
// just has to revalidate it. Pairing it with a version ETag keeps the common
// case a 304 with an empty body, so this costs a conditional request, not a
// re-download.
func revalidatingAssets(next http.Handler) http.Handler {
	etag := `"` + appVersion + `"`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", etag)
		if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		next.ServeHTTP(w, r)
	})
}
