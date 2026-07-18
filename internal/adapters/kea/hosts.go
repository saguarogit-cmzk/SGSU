package kea

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Reservation is one static host entry in Kea's hosts table. Only
// MAC-identified IPv4 reservations are managed in this milestone
// (dhcp_identifier_type 0 = hw-address).
type Reservation struct {
	ID       int64  `json:"id"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	SubnetID int64  `json:"subnetId"`
}

// HostStore manages reservations directly in Kea's PostgreSQL backend; Kea
// queries the hosts table per DHCP transaction, so inserts are effective
// immediately without touching the config file.
type HostStore struct{ db *sql.DB }

func OpenHosts(dsn string) (*HostStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &HostStore{db: db}, nil
}

func (h *HostStore) Close() error { return h.db.Close() }

var macRe = regexp.MustCompile(`^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$`)

// NormalizeMAC validates and returns the bare-hex form Kea stores
// ("aa:bb:cc:dd:ee:ff" -> "aabbccddeeff").
func NormalizeMAC(mac string) (string, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return "", fmt.Errorf("invalid MAC address %q (expected aa:bb:cc:dd:ee:ff)", mac)
	}
	return strings.NewReplacer(":", "", "-", "").Replace(mac), nil
}

// FormatMACHex renders stored bare hex back as aa:bb:cc:dd:ee:ff.
func FormatMACHex(hexMAC string) string {
	if len(hexMAC) != 12 {
		return hexMAC
	}
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = hexMAC[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}

// IP4ToInt converts a dotted IPv4 address into the host-byte-order integer
// Kea stores in hosts.ipv4_address.
func IP4ToInt(s string) (int64, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return 0, fmt.Errorf("invalid IPv4 address %q", s)
	}
	v4 := ip.To4()
	return int64(v4[0])<<24 | int64(v4[1])<<16 | int64(v4[2])<<8 | int64(v4[3]), nil
}

// IntToIP4 is the inverse of IP4ToInt.
func IntToIP4(v int64) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (h *HostStore) List(ctx context.Context, subnetID int64) ([]Reservation, error) {
	q := `SELECT host_id, encode(dhcp_identifier, 'hex'), COALESCE(ipv4_address, 0),
		COALESCE(hostname, ''), COALESCE(dhcp4_subnet_id, 0)
		FROM hosts WHERE dhcp_identifier_type = 0`
	args := []any{}
	if subnetID > 0 {
		args = append(args, subnetID)
		q += ` AND dhcp4_subnet_id = $1`
	}
	q += ` ORDER BY ipv4_address`
	rows, err := h.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Reservation
	for rows.Next() {
		var r Reservation
		var macHex string
		var ipInt int64
		if err := rows.Scan(&r.ID, &macHex, &ipInt, &r.Hostname, &r.SubnetID); err != nil {
			return nil, err
		}
		r.MAC = FormatMACHex(macHex)
		r.IP = IntToIP4(ipInt)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (h *HostStore) Add(ctx context.Context, r Reservation) (int64, error) {
	macHex, err := NormalizeMAC(r.MAC)
	if err != nil {
		return 0, err
	}
	ipInt, err := IP4ToInt(r.IP)
	if err != nil {
		return 0, err
	}
	if r.SubnetID <= 0 {
		return 0, fmt.Errorf("subnetId is required")
	}
	macBytes, err := hex.DecodeString(macHex)
	if err != nil {
		return 0, err
	}
	var id int64
	err = h.db.QueryRowContext(ctx, `INSERT INTO hosts
		(dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname)
		VALUES ($1, 0, $2, $3, $4) RETURNING host_id`,
		macBytes, r.SubnetID, ipInt, r.Hostname).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert reservation: %w", err)
	}
	return id, nil
}

func (h *HostStore) Delete(ctx context.Context, hostID int64) (bool, error) {
	res, err := h.db.ExecContext(ctx, `DELETE FROM hosts WHERE host_id = $1 AND dhcp_identifier_type = 0`, hostID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
