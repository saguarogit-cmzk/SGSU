package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"saguaro.local/network-manager/internal/adapters/ipsec"
	"saguaro.local/network-manager/internal/adapters/kea"
	"saguaro.local/network-manager/internal/adapters/multiwan"
	"saguaro.local/network-manager/internal/adapters/nftgen"
	"saguaro.local/network-manager/internal/adapters/nginxgen"
	routesmod "saguaro.local/network-manager/internal/adapters/routes"
	rpzmod "saguaro.local/network-manager/internal/adapters/rpz"
	"saguaro.local/network-manager/internal/adapters/s2s"
	"saguaro.local/network-manager/internal/adapters/squidcfg"
	"saguaro.local/network-manager/internal/adapters/wancfg"
	"saguaro.local/network-manager/internal/adapters/wireguard"
	evstore "saguaro.local/network-manager/internal/events"
	mailmod "saguaro.local/network-manager/internal/mail"
)

//go:embed web/*
var webFS embed.FS

type service struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Enabled     bool   `json:"enabled"`
}

type auditEvent struct {
	ID       string         `json:"id"`
	Time     time.Time      `json:"time"`
	Severity string         `json:"severity"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	Target   string         `json:"target"`
	Result   string         `json:"result"`
	RemoteIP string         `json:"remoteIp"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type state struct {
	Version   int               `json:"version"`
	Services  []service         `json:"services"`
	Audit     []auditEvent      `json:"audit"`
	Mail      *mailmod.Config   `json:"mail,omitempty"`
	Gateway   *nftgen.Config    `json:"gateway,omitempty"`
	IDS       *idsState         `json:"ids,omitempty"`
	RPZ       *rpzmod.Config    `json:"rpz,omitempty"`
	ProxyApps []nginxgen.App    `json:"proxyApps,omitempty"`
	Certs     []certRecord      `json:"certs,omitempty"`
	VPN       *wireguard.Config `json:"vpn,omitempty"`
	Backup    *backupConfig     `json:"backup,omitempty"`
	MultiWAN  *multiwan.Config  `json:"multiWan,omitempty"`
	Routes    *routesmod.Config `json:"routes,omitempty"`
	S2S       *s2s.Config       `json:"s2s,omitempty"`
	IPsec     *ipsec.Config     `json:"ipsec,omitempty"`
	// SystemProfile is the deployment mode: "gateway" (firewall/gateway/VPN) or
	// "router" (local DHCP/DNS/router behind another gateway).
	SystemProfile string `json:"systemProfile,omitempty"`
	// BlockedMACs are DHCP clients refused a lease via Kea's DROP class.
	BlockedMACs []string `json:"blockedMacs,omitempty"`
	// WANConfig is the legacy single WAN (migrated into WANConfigs on load).
	WANConfig *wancfg.WAN `json:"wanConfig,omitempty"`
	// WANConfigs is the WAN uplink addressing for one or more WAN interfaces.
	WANConfigs []wancfg.WAN `json:"wanConfigs,omitempty"`
	// SIEM is the external log-forwarding configuration.
	SIEM *siemConfig `json:"siem,omitempty"`
	// WebProxy is the Squid/e2guardian caching+filtering proxy configuration.
	WebProxy *squidcfg.Config `json:"webProxy,omitempty"`
	// NICLabels maps a kernel interface name to an operator-friendly alias.
	NICLabels map[string]string `json:"nicLabels,omitempty"`
}

type store struct {
	mu   sync.RWMutex
	path string
	data state
}

type app struct {
	log            *slog.Logger
	store          *store
	adminUser      string
	users          userStore
	dummyPHC       string // constant-cost verify target for unknown usernames
	sessions       sessionStore
	sessionTTL     time.Duration
	secure         bool
	ipLimiter      *loginLimiter
	userLimiter    *loginLimiter
	events         *evstore.Store // nil without PostgreSQL (development)
	mailKey        []byte         // AES-256 key for the stored SMTP password
	keaHosts       *kea.HostStore // nil without SAGUARO_KEA_DB_DSN
	runFirewall    func(ctx context.Context, action string) ([]byte, error)
	runIDS         func(ctx context.Context, args ...string) ([]byte, error)
	runRPZ         func(ctx context.Context, action string) ([]byte, error)
	runProxy       func(ctx context.Context, action string) ([]byte, error)
	runWebProxy    func(ctx context.Context, args ...string) ([]byte, error)
	probeUpstream  func(ctx context.Context, addr string) error
	runCert        func(ctx context.Context, args ...string) ([]byte, error)
	runVPN         func(ctx context.Context, action string) ([]byte, error)
	runBackupCfg   func(ctx context.Context, action string) ([]byte, error)
	runWAN         func(ctx context.Context, action string) ([]byte, error)
	runRoute       func(ctx context.Context, action string) ([]byte, error)
	runS2S         func(ctx context.Context, action string) ([]byte, error)
	runIPsec       func(ctx context.Context, action string) ([]byte, error)
	runSvc         func(ctx context.Context, args ...string) ([]byte, error)
	runLogs        func(ctx context.Context, args ...string) ([]byte, error)
	runTools       func(ctx context.Context, args ...string) ([]byte, error)
	runPkg         func(ctx context.Context, args ...string) ([]byte, error)
	runNet         func(ctx context.Context, args ...string) ([]byte, error)
	readInterfaces func(ctx context.Context) ([]nicInfo, error)
	hwMemMB        int
	hwCores        int
	cpuMu          sync.Mutex
	cpuPrev        *cpuStat
	siem           *siemForwarder

	// component endpoints used by health checks
	resolverAddr string
	pdnsURL      string
	pdnsKey      string
	keaURL       string
	keaUser      string
	keaPass      string
}

const appVersion = "0.45.0"

// ctxKeySession carries the authenticated session's token hash through a request.
type ctxKeySession struct{}

func main() {
	dataDir := env("SAGUARO_DATA_DIR", "/var/lib/saguaro")
	listen := env("SAGUARO_LISTEN", "127.0.0.1:9080")
	adminUser := env("SAGUARO_ADMIN_USER", "admin")
	adminPass := loadAdminPassword()
	if len(adminPass) < 14 {
		fmt.Fprintln(os.Stderr, "administrator password must contain at least 14 characters; provide it via systemd LoadCredential=admin-password, SAGUARO_ADMIN_PASSWORD_FILE or SAGUARO_ADMIN_PASSWORD")
		os.Exit(2)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		panic(err)
	}
	s, err := openStore(filepath.Join(dataDir, "state.json"))
	if err != nil {
		panic(err)
	}
	seedProfile(s)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	passPHC, err := hashPassword(adminPass)
	if err != nil {
		panic(err)
	}
	var sessions sessionStore
	var users userStore
	var eventStore *evstore.Store
	if dsn := os.Getenv("SAGUARO_DB_DSN"); dsn != "" {
		pgSess, err := openPGSessions(dsn)
		if err != nil {
			logger.Error("cannot open PostgreSQL session store", "error", err)
			os.Exit(1)
		}
		sessions = pgSess
		logger.Info("session store: postgresql")
		users, err = openPGUsers(pgSess.db)
		if err != nil {
			logger.Error("cannot open PostgreSQL user store", "error", err)
			os.Exit(1)
		}
		eventStore, err = evstore.Open(dsn)
		if err != nil {
			logger.Error("cannot open event store", "error", err)
			os.Exit(1)
		}
		if err := eventStore.EnsureSchema(context.Background()); err != nil {
			logger.Error("cannot ensure event schema", "error", err)
			os.Exit(1)
		}
	} else {
		sessions, err = openFileSessions(filepath.Join(dataDir, "sessions.json"))
		if err != nil {
			panic(err)
		}
		users, err = openFileUsers(filepath.Join(dataDir, "users.json"))
		if err != nil {
			panic(err)
		}
		logger.Info("session store: file", "path", filepath.Join(dataDir, "sessions.json"))
	}
	if created, err := seedAdmin(users, adminUser, passPHC); err != nil {
		logger.Error("cannot seed administrator", "error", err)
		os.Exit(1)
	} else if created {
		logger.Info("seeded bootstrap administrator", "username", adminUser)
	}
	mailKey, err := mailmod.LoadOrCreateKey(env("SAGUARO_SECRET_KEY_FILE", filepath.Join(dataDir, "secret.key")))
	if err != nil {
		logger.Warn("secret key unavailable; SMTP password storage disabled", "error", err)
		mailKey = nil
	}
	var keaHosts *kea.HostStore
	if dsn := os.Getenv("SAGUARO_KEA_DB_DSN"); dsn != "" {
		keaHosts, err = kea.OpenHosts(dsn)
		if err != nil {
			logger.Error("cannot open Kea host database; reservations disabled", "error", err)
			keaHosts = nil
		}
	}
	a := &app{
		log:        logger,
		store:      s,
		adminUser:  adminUser,
		users:      users,
		dummyPHC:   passPHC,
		sessions:   sessions,
		sessionTTL: time.Duration(atoi(env("SAGUARO_SESSION_HOURS", "8"), 8)) * time.Hour,
		secure:     env("SAGUARO_SECURE_COOKIE", "true") == "true",

		ipLimiter:      newLoginLimiter(),
		userLimiter:    newLoginLimiter(),
		events:         eventStore,
		mailKey:        mailKey,
		keaHosts:       keaHosts,
		runFirewall:    defaultRunFirewall,
		runIDS:         defaultRunIDS,
		runRPZ:         defaultRunRPZ,
		runProxy:       defaultRunProxy,
		runWebProxy:    defaultRunWebProxy,
		probeUpstream:  defaultProbeUpstream,
		runCert:        defaultRunCert,
		runVPN:         defaultRunVPN,
		runBackupCfg:   defaultRunBackupCfg,
		runWAN:         defaultRunWAN,
		runRoute:       defaultRunRoute,
		runS2S:         defaultRunS2S,
		runIPsec:       defaultRunIPsec,
		runSvc:         defaultRunSvc,
		runLogs:        defaultRunLogs,
		runTools:       defaultRunTools,
		runPkg:         defaultRunPkg,
		runNet:         defaultRunNet,
		readInterfaces: defaultReadInterfaces,
		hwMemMB:        readMemTotalMB(),
		hwCores:        runtime.NumCPU(),

		resolverAddr: env("SAGUARO_RESOLVER_ADDR", "127.0.0.1:53"),
		pdnsURL:      os.Getenv("SAGUARO_PDNS_API_URL"),
		pdnsKey:      os.Getenv("SAGUARO_PDNS_API_KEY"),
		keaURL:       os.Getenv("SAGUARO_KEA_API_URL"),
		keaUser:      os.Getenv("SAGUARO_KEA_API_USER"),
		keaPass:      os.Getenv("SAGUARO_KEA_API_PASSWORD"),
	}
	hostname, _ := os.Hostname()
	a.siem = newSIEMForwarder(hostname, appVersion, logger)
	if s.data.SIEM != nil {
		a.siem.setConfig(*s.data.SIEM)
	}
	if err := a.sessions.PruneExpired(time.Now()); err != nil {
		a.log.Error("session prune failed", "error", err)
	}
	go func() {
		for range time.Tick(time.Hour) {
			if err := a.sessions.PruneExpired(time.Now()); err != nil {
				a.log.Error("session prune failed", "error", err)
			}
			a.ipLimiter.prune(time.Now())
			a.userLimiter.prune(time.Now())
		}
	}()
	go func() {
		// One early sweep so the dashboard shows real statuses shortly after
		// boot, then a periodic refresh.
		time.Sleep(5 * time.Second)
		a.runHealthChecks(context.Background())
		interval := time.Duration(atoi(env("SAGUARO_HEALTH_INTERVAL_MIN", "5"), 5)) * time.Minute
		for range time.Tick(interval) {
			a.runHealthChecks(context.Background())
		}
	}()
	go a.alertLoop()
	go func() {
		// Daily restore-drill reminder (W11): a Warning event when overdue.
		for {
			a.checkRestoreDrill()
			time.Sleep(24 * time.Hour)
		}
	}()
	srv := &http.Server{Addr: listen, Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	a.log.Info("saguaro starting", "listen", listen, "dataDir", dataDir)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		a.log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func (a *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.auth(a.logout))
	mux.HandleFunc("GET /api/health", a.health)
	mux.HandleFunc("GET /api/health/deep", a.auth(a.healthDeep))
	mux.HandleFunc("GET /api/dashboard", a.auth(a.dashboard))
	mux.HandleFunc("GET /api/services", a.auth(a.services))
	mux.HandleFunc("POST /api/services/{id}/actions/{action}", a.authz(permServiceCheck, a.serviceAction))
	mux.HandleFunc("GET /api/dhcp/blocklist", a.auth(a.apiDHCPBlockList))
	mux.HandleFunc("POST /api/dhcp/blocklist", a.authz(permDHCPWrite, a.apiDHCPBlockAdd))
	mux.HandleFunc("DELETE /api/dhcp/blocklist/{mac}", a.authz(permDHCPWrite, a.apiDHCPBlockDelete))
	mux.HandleFunc("GET /api/conflicts", a.auth(a.apiConflicts))
	mux.HandleFunc("GET /api/siem", a.auth(a.apiSIEMGet))
	mux.HandleFunc("PUT /api/siem", a.authz(permMailWrite, a.apiSIEMPut))
	mux.HandleFunc("POST /api/siem/test", a.authz(permMailWrite, a.apiSIEMTest))
	mux.HandleFunc("GET /api/svcctl", a.authz(permServiceCheck, a.apiSvcCtlList))
	mux.HandleFunc("POST /api/svcctl/{key}/{action}", a.authz(permServiceControl, a.apiSvcCtlAction))
	mux.HandleFunc("GET /api/packages", a.authz(permServiceCheck, a.apiPkgList))
	mux.HandleFunc("POST /api/packages/refresh", a.authz(permPackages, a.apiPkgRefresh))
	mux.HandleFunc("POST /api/packages/upgrade/{key}", a.authz(permPackages, a.apiPkgUpgrade))
	mux.HandleFunc("POST /api/packages/unattended", a.authz(permPackages, a.apiPkgUnattended))
	mux.HandleFunc("GET /api/audit", a.auth(a.audit))
	mux.HandleFunc("GET /api/events", a.auth(a.apiEvents))
	mux.HandleFunc("GET /api/mail", a.auth(a.apiMailGet))
	mux.HandleFunc("PUT /api/mail", a.authz(permMailWrite, a.apiMailPut))
	mux.HandleFunc("POST /api/mail/test", a.authz(permMailWrite, a.apiMailTest))
	mux.HandleFunc("GET /api/dns/zones", a.auth(a.apiDNSZones))
	mux.HandleFunc("POST /api/dns/zones", a.authz(permDNSWrite, a.apiDNSZoneCreate))
	mux.HandleFunc("GET /api/dns/zones/{zone}", a.auth(a.apiDNSZoneGet))
	mux.HandleFunc("DELETE /api/dns/zones/{zone}", a.authz(permDNSWrite, a.apiDNSZoneDelete))
	mux.HandleFunc("PUT /api/dns/zones/{zone}/records", a.authz(permDNSWrite, a.apiDNSRecordPut))
	mux.HandleFunc("GET /api/dhcp/status", a.auth(a.apiDHCPStatus))
	mux.HandleFunc("GET /api/dhcp/subnets", a.auth(a.apiDHCPSubnets))
	mux.HandleFunc("POST /api/dhcp/subnets", a.authz(permDHCPWrite, a.apiDHCPSubnetAdd))
	mux.HandleFunc("PUT /api/dhcp/subnets/{id}", a.authz(permDHCPWrite, a.apiDHCPSubnetUpdate))
	mux.HandleFunc("DELETE /api/dhcp/subnets/{id}", a.authz(permDHCPWrite, a.apiDHCPSubnetDelete))
	mux.HandleFunc("GET /api/dhcp/leases", a.auth(a.apiDHCPLeases))
	mux.HandleFunc("GET /api/dhcp/reservations", a.auth(a.apiDHCPReservations))
	mux.HandleFunc("POST /api/dhcp/reservations", a.authz(permDHCPWrite, a.apiDHCPReservationAdd))
	mux.HandleFunc("DELETE /api/dhcp/reservations/{id}", a.authz(permDHCPWrite, a.apiDHCPReservationDelete))
	mux.HandleFunc("GET /api/sessions", a.auth(a.listSessions))
	mux.HandleFunc("POST /api/sessions/{id}/revoke", a.authz(permSessions, a.revokeSession))
	mux.HandleFunc("GET /api/users", a.authz(permUsersWrite, a.apiUsersList))
	mux.HandleFunc("POST /api/users", a.authz(permUsersWrite, a.apiUserCreate))
	mux.HandleFunc("PATCH /api/users/{name}", a.authz(permUsersWrite, a.apiUserUpdate))
	mux.HandleFunc("DELETE /api/users/{name}", a.authz(permUsersWrite, a.apiUserDelete))
	mux.HandleFunc("GET /api/gateway", a.auth(a.apiGatewayGet))
	mux.HandleFunc("PUT /api/gateway", a.authz(permFirewall, a.apiGatewayPut))
	mux.HandleFunc("GET /api/gateway/preview", a.auth(a.apiGatewayPreview))
	mux.HandleFunc("POST /api/gateway/apply", a.authz(permFirewall, a.apiGatewayApply))
	mux.HandleFunc("POST /api/gateway/confirm", a.authz(permFirewall, a.apiGatewayConfirm))
	mux.HandleFunc("POST /api/gateway/rollback", a.authz(permFirewall, a.apiGatewayRollback))
	mux.HandleFunc("GET /api/firewall", a.auth(a.apiFirewallGet))
	mux.HandleFunc("PUT /api/firewall/aliases", a.authz(permFirewall, a.apiFirewallAliasesPut))
	mux.HandleFunc("PUT /api/firewall/rules", a.authz(permFirewall, a.apiFirewallRulesPut))
	mux.HandleFunc("POST /api/firewall/apply", a.authz(permFirewall, a.apiFirewallApply))
	mux.HandleFunc("POST /api/firewall/test", a.auth(a.apiFirewallTest))
	mux.HandleFunc("GET /api/metrics", a.auth(a.apiMetrics))
	mux.HandleFunc("GET /api/logs/unbound", a.auth(a.apiUnboundStats))
	mux.HandleFunc("GET /api/logs/suricata", a.auth(a.apiSuricataAlerts))
	mux.HandleFunc("POST /api/tools", a.authz(permServiceCheck, a.apiToolRun))
	mux.HandleFunc("GET /api/webproxy", a.auth(a.apiWebProxyGet))
	mux.HandleFunc("PUT /api/webproxy", a.authz(permProxy, a.apiWebProxyPut))
	mux.HandleFunc("GET /api/wan", a.auth(a.apiWANConfigGet))
	mux.HandleFunc("POST /api/wan/apply", a.authz(permFirewall, a.apiWANConfigApply))
	mux.HandleFunc("GET /api/interfaces", a.auth(a.apiInterfacesList))
	mux.HandleFunc("POST /api/interfaces/{name}/identify", a.authz(permFirewall, a.apiInterfaceIdentify))
	mux.HandleFunc("PUT /api/interfaces/{name}/label", a.authz(permFirewall, a.apiInterfaceLabel))
	mux.HandleFunc("GET /api/backup", a.auth(a.apiBackupGet))
	mux.HandleFunc("POST /api/backup/apply", a.authz(permBackup, a.apiBackupApply))
	mux.HandleFunc("POST /api/backup/run", a.authz(permBackup, a.apiBackupRunNow))
	mux.HandleFunc("POST /api/backup/drill", a.authz(permBackup, a.apiBackupMarkDrill))
	mux.HandleFunc("GET /api/multiwan", a.auth(a.apiWANGet))
	mux.HandleFunc("POST /api/multiwan/apply", a.authz(permFirewall, a.apiWANApply))
	mux.HandleFunc("GET /api/routes", a.auth(a.apiRoutesGet))
	mux.HandleFunc("PUT /api/routes", a.authz(permFirewall, a.apiRoutesPut))
	mux.HandleFunc("GET /api/s2s", a.auth(a.apiS2SGet))
	mux.HandleFunc("POST /api/s2s/apply", a.authz(permFirewall, a.apiS2SApply))
	mux.HandleFunc("POST /api/s2s/sites", a.authz(permFirewall, a.apiS2SSiteAdd))
	mux.HandleFunc("DELETE /api/s2s/sites/{name}", a.authz(permFirewall, a.apiS2SSiteDelete))
	mux.HandleFunc("GET /api/ipsec", a.auth(a.apiIPsecGet))
	mux.HandleFunc("POST /api/ipsec/apply", a.authz(permFirewall, a.apiIPsecApply))
	mux.HandleFunc("POST /api/ipsec/connections", a.authz(permFirewall, a.apiIPsecConnAdd))
	mux.HandleFunc("DELETE /api/ipsec/connections/{name}", a.authz(permFirewall, a.apiIPsecConnDelete))
	mux.HandleFunc("GET /api/vpn", a.auth(a.apiVPNGet))
	mux.HandleFunc("POST /api/vpn/apply", a.authz(permFirewall, a.apiVPNApply))
	mux.HandleFunc("POST /api/vpn/peers", a.authz(permFirewall, a.apiVPNPeerAdd))
	mux.HandleFunc("DELETE /api/vpn/peers/{name}", a.authz(permFirewall, a.apiVPNPeerDelete))
	mux.HandleFunc("GET /api/certs", a.auth(a.apiCertsList))
	mux.HandleFunc("POST /api/certs/issue", a.authz(permCerts, a.apiCertIssue))
	mux.HandleFunc("POST /api/certs/{name}/deploy-gui", a.authz(permCerts, a.apiCertDeployGUI))
	mux.HandleFunc("DELETE /api/certs/{name}", a.authz(permCerts, a.apiCertDelete))
	mux.HandleFunc("GET /api/proxy", a.auth(a.apiProxyGet))
	mux.HandleFunc("POST /api/proxy/apply", a.authz(permProxy, a.apiProxyApply))
	mux.HandleFunc("GET /api/rpz", a.auth(a.apiRPZGet))
	mux.HandleFunc("POST /api/rpz/apply", a.authz(permDNSWrite, a.apiRPZApply))
	mux.HandleFunc("GET /api/ids", a.auth(a.apiIDSGet))
	mux.HandleFunc("POST /api/ids/enable", a.authz(permFirewall, a.apiIDSEnable))
	mux.HandleFunc("POST /api/ids/disable", a.authz(permFirewall, a.apiIDSDisable))
	mux.HandleFunc("GET /api/system", a.auth(a.apiSystemGet))
	mux.HandleFunc("PUT /api/system/profile", a.authz(permFirewall, a.apiSystemProfilePut))
	mux.HandleFunc("GET /api/profile", a.auth(a.apiProfile))
	mux.HandleFunc("POST /api/profile/password", a.auth(a.apiProfilePassword))
	assets, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return securityHeaders(a.requestLog(mux))
}

func openStore(path string) (*store, error) {
	s := &store{path: path, data: state{Version: 1, Services: defaultServices()}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("invalid state file: %w", err)
	}
	// Services added in newer releases must appear on upgraded installs too.
	have := map[string]bool{}
	for _, svc := range s.data.Services {
		have[svc.ID] = true
	}
	added := false
	for _, d := range defaultServices() {
		if !have[d.ID] {
			s.data.Services = append(s.data.Services, d)
			added = true
		}
	}
	if added {
		return s, s.saveLocked()
	}
	return s, nil
}

func defaultServices() []service {
	return []service{
		{ID: "postgresql", Name: "PostgreSQL", Description: "Configuration, events, Kea and PowerDNS database", Status: "not-configured"},
		{ID: "unbound", Name: "Unbound", Description: "Recursive DNS resolver for clients", Status: "not-configured"},
		{ID: "pdns", Name: "PowerDNS Authoritative", Description: "Local authoritative zones with HTTP API", Status: "not-configured"},
		{ID: "kea", Name: "Kea DHCP", Description: "DHCPv4/v6, reservations and client classes", Status: "not-configured"},
		{ID: "kea-ddns", Name: "Kea DDNS", Description: "Automatic A/PTR updates from DHCP leases", Status: "not-configured"},
		{ID: "saguaro-eventd", Name: "Event Collector", Description: "journald to PostgreSQL structured events (layer 2 logging)", Status: "not-configured"},
		{ID: "step-ca", Name: "Step CA", Description: "Internal certificate authority", Status: "not-configured"},
		{ID: "nginx", Name: "Nginx", Description: "TLS reverse proxy", Status: "not-configured"},
		{ID: "nftables", Name: "nftables", Description: "Host and gateway firewall", Status: "not-configured"},
	}
}

func (s *store) saveLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *store) addAudit(e auditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Audit = append([]auditEvent{e}, s.data.Audit...)
	if len(s.data.Audit) > 5000 {
		s.data.Audit = s.data.Audit[:5000]
	}
	return s.saveLocked()
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	ip := remoteIP(r)
	now := time.Now().UTC()
	if locked, retry := a.ipLimiter.check("ip:"+ip, now); locked {
		writeLocked(w, retry)
		return
	}
	if locked, retry := a.userLimiter.check("user:"+in.Username, now); locked {
		writeLocked(w, retry)
		return
	}
	rec0, found, lookupErr := a.users.Get(strings.ToLower(strings.TrimSpace(in.Username)))
	if lookupErr != nil {
		writeError(w, http.StatusInternalServerError, "user store unavailable")
		return
	}
	phc := a.dummyPHC
	if found {
		phc = rec0.PHC
	}
	if !verifyPassword(in.Password, phc) || !found || !rec0.Enabled {
		time.Sleep(350 * time.Millisecond)
		lockIP := a.ipLimiter.fail("ip:"+ip, now)
		lockUser := a.userLimiter.fail("user:"+in.Username, now)
		a.record(r, in.Username, "login", "control-plane", "denied", nil)
		if lock := maxDuration(lockIP, lockUser); lock > 0 {
			a.recordSev(r, in.Username, "login-lockout", "control-plane", "locked", "security",
				map[string]any{"lockSeconds": int(lock.Seconds())})
			writeLocked(w, lock)
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	a.ipLimiter.success("ip:" + ip)
	a.userLimiter.success("user:" + in.Username)
	token := randomToken()
	csrf := randomToken()
	tokenHash := hashToken(token)
	rec := sessionRecord{TokenHash: tokenHash, ID: sessionID(tokenHash), Username: rec0.Username, CreatedAt: now, ExpiresAt: now.Add(a.sessionTTL), RemoteIP: ip, CSRFHash: hashToken(csrf)}
	if err := a.sessions.Create(rec); err != nil {
		a.log.Error("session create failed", "error", err)
		writeError(w, http.StatusInternalServerError, "session store unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "saguaro_session", Value: token, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(a.sessionTTL.Seconds())})
	// Deliberately not HttpOnly: the SPA reads this cookie and echoes it in the
	// X-CSRF-Token header, which the auth middleware checks against the session.
	http.SetCookie(w, &http.Cookie{Name: "saguaro_csrf", Value: csrf, Path: "/", HttpOnly: false, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(a.sessionTTL.Seconds())})
	a.record(r, rec0.Username, "login", "control-plane", "success", map[string]any{"sessionId": rec.ID, "role": rec0.Role})
	writeJSON(w, http.StatusOK, map[string]any{"user": rec0.Username, "role": rec0.Role, "mustChangePassword": rec0.MustChangePassword})
}

func mustChangeAllowed(r *http.Request) bool {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/profile":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/api/profile/password":
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/api/logout":
		return true
	}
	return false
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeLocked(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed logins; retry in %ds", secs))
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("saguaro_session"); err == nil {
		if err := a.sessions.Delete(hashToken(c.Value)); err != nil {
			a.log.Error("session delete failed", "error", err)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "saguaro_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "saguaro_csrf", Path: "/", MaxAge: -1, Secure: a.secure, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("saguaro_session")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		tokenHash := hashToken(c.Value)
		rec, ok, err := a.sessions.Get(tokenHash)
		if err != nil {
			a.log.Error("session lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "session store unavailable")
			return
		}
		if ok && time.Now().After(rec.ExpiresAt) {
			if err := a.sessions.Delete(tokenHash); err != nil {
				a.log.Error("session delete failed", "error", err)
			}
			ok = false
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			header := r.Header.Get("X-CSRF-Token")
			if header == "" || rec.CSRFHash == "" ||
				subtle.ConstantTimeCompare([]byte(hashToken(header)), []byte(rec.CSRFHash)) != 1 {
				a.recordSev(r, rec.Username, "csrf-reject", r.URL.Path, "denied", "security", nil)
				writeError(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
		}
		user, userOK := a.resolveUser(r.Context(), rec.Username)
		if !userOK {
			// The account was deleted or disabled after login.
			if err := a.sessions.Delete(tokenHash); err != nil {
				a.log.Error("session delete failed", "error", err)
			}
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// Wizard W1: a pending forced password change blocks everything except
		// the change itself, the profile view and logout.
		if user.MustChangePassword && !mustChangeAllowed(r) {
			writeError(w, http.StatusForbidden, "password change required before continuing")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeySession{}, tokenHash)
		ctx = context.WithValue(ctx, ctxKeyUser{}, user)
		next(w, r.WithContext(ctx))
	}
}

func (a *app) listSessions(w http.ResponseWriter, r *http.Request) {
	recs, err := a.sessions.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session store unavailable")
		return
	}
	current, _ := r.Context().Value(ctxKeySession{}).(string)
	type view struct {
		ID        string    `json:"id"`
		Username  string    `json:"username"`
		CreatedAt time.Time `json:"createdAt"`
		ExpiresAt time.Time `json:"expiresAt"`
		RemoteIP  string    `json:"remoteIp"`
		Current   bool      `json:"current"`
	}
	out := make([]view, 0, len(recs))
	for _, rec := range recs {
		out = append(out, view{ID: rec.ID, Username: rec.Username, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt, RemoteIP: rec.RemoteIP, Current: rec.TokenHash == current})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *app) revokeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	removed, err := a.sessions.DeleteByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session store unavailable")
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	a.record(r, a.actor(r), "session-revoke", id, "success", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// health is the unauthenticated liveness probe: it confirms only that the
// control plane answers. Component details require an authenticated session.
func (a *app) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": appVersion})
}

func (a *app) healthDeep(w http.ResponseWriter, r *http.Request) {
	results := a.runHealthChecks(r.Context())
	healthy := 0
	for _, res := range results {
		if res.Status == "healthy" {
			healthy++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"healthy": healthy, "total": len(results), "checks": results})
}

func (a *app) dashboard(w http.ResponseWriter, _ *http.Request) {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	configured, healthy := 0, 0
	for _, s := range a.store.data.Services {
		if s.Enabled {
			configured++
		}
		if s.Status == "healthy" {
			healthy++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": len(a.store.data.Services), "configured": configured, "healthy": healthy, "alerts": 0, "recentAudit": first(a.store.data.Audit, 8)})
}

func (a *app) services(w http.ResponseWriter, _ *http.Request) {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	writeJSON(w, http.StatusOK, a.store.data.Services)
}

func (a *app) serviceAction(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	if action != "check" {
		writeError(w, http.StatusNotImplemented, "only safe health checks are enabled in this milestone")
		return
	}
	res, ok := a.runHealthCheck(r.Context(), id)
	if !ok {
		writeError(w, http.StatusNotFound, "service not found")
		return
	}
	a.record(r, a.actor(r), "health-check", id, res.Status, map[string]any{"detail": res.Detail, "latencyMs": res.LatencyMs})
	writeJSON(w, http.StatusOK, map[string]any{"result": res})
}

func (a *app) audit(w http.ResponseWriter, _ *http.Request) {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	writeJSON(w, http.StatusOK, first(a.store.data.Audit, 200))
}

func (a *app) record(r *http.Request, actor, action, target, result string, meta map[string]any) {
	a.recordSev(r, actor, action, target, result, "info", meta)
}

func (a *app) recordSev(r *http.Request, actor, action, target, result, severity string, meta map[string]any) {
	e := auditEvent{ID: newID(), Time: time.Now().UTC(), Severity: severity, Actor: actor, Action: action, Target: target, Result: result, RemoteIP: remoteIP(r), Metadata: meta}
	if err := a.store.addAudit(e); err != nil {
		a.log.Error("audit persistence failed", "error", err)
	}
	a.siemForward(e)
	if severity == "security" {
		a.log.Warn("security event", "action", action, "actor", actor, "target", target, "remote", remoteIP(r))
	}
	if a.events == nil {
		return
	}
	// Layer 2: the same record goes to the append-only audit_log; security
	// events additionally land in the events table for alerting and reports.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var metaJSON json.RawMessage
	if meta != nil {
		metaJSON, _ = json.Marshal(meta)
	}
	if err := a.events.InsertAudit(ctx, evstore.AuditEntry{
		TS: e.Time, Actor: actor, Action: action, Target: target,
		NewValue: metaJSON, Result: result, RemoteIP: remoteIP(r),
	}); err != nil {
		a.log.Error("audit_log insert failed", "error", err)
	}
	if severity == "security" {
		if err := a.events.Insert(ctx, evstore.Event{
			TS: e.Time, Module: "control-plane", Severity: "security",
			Username: actor, SrcIP: remoteIP(r), Action: action, Result: result,
			Message: fmt.Sprintf("%s %s (%s)", action, target, result), Raw: metaJSON,
		}); err != nil {
			a.log.Error("security event insert failed", "error", err)
		}
	}
}

// apiEvents serves the layer-2 event listing. Without PostgreSQL there is no
// event store, which is an explicit condition rather than an empty result.
func (a *app) apiEvents(w http.ResponseWriter, r *http.Request) {
	if a.events == nil {
		writeError(w, http.StatusServiceUnavailable, "event store requires PostgreSQL (SAGUARO_DB_DSN)")
		return
	}
	q := r.URL.Query()
	sev := q.Get("severity")
	if sev != "" && !evstore.ValidSeverity(sev) {
		writeError(w, http.StatusBadRequest, "invalid severity")
		return
	}
	opts := evstore.QueryOpts{Module: q.Get("module"), Severity: sev, Limit: atoi(q.Get("limit"), 100)}
	out, err := a.events.Query(r.Context(), opts)
	if err != nil {
		a.log.Error("event query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "event query failed")
		return
	}
	if out == nil {
		out = []evstore.Event{}
	}
	writeJSON(w, http.StatusOK, out)
}

// loadAdminPassword prefers file-based sources so the secret never has to live in
// an environment file: systemd LoadCredential first, then an explicit file path,
// then the plain environment variable for development runs.
func loadAdminPassword() string {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "admin-password")); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	if path := os.Getenv("SAGUARO_ADMIN_PASSWORD_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read SAGUARO_ADMIN_PASSWORD_FILE: %v\n", err)
			os.Exit(2)
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv("SAGUARO_ADMIN_PASSWORD")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
func (a *app) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		a.log.Info("http request", "method", r.Method, "path", r.URL.Path, "durationMs", time.Since(start).Milliseconds(), "remote", remoteIP(r))
	})
}
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		writeError(w, 400, "invalid JSON")
		return err
	}
	if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, 400, "request must contain one JSON object")
		return errors.New("trailing JSON")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
func newID() string { b := make([]byte, 12); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func remoteIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
func first[T any](items []T, n int) []T {
	if len(items) < n {
		n = len(items)
	}
	return items[:n]
}
func atoi(s string, fallback int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}
