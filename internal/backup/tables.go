package backup

// Every table in SGC's database is listed here as either exported or
// transient. TestEveryTableIsClassified fails if a table exists that is in
// neither list, so adding a table forces the decision: does this travel with
// an export or not?

// exportedTables are copied into an export as they are.
var exportedTables = []string{
	"admin",     // the admin account
	"audit_log", // history of who did what
	"setting",   // settings (with a few bookkeeping keys removed below)
	"ssh_key",   // SSH keys added in SGC's page (public keys)
	// Services and the tokens that announced them: servers keep their
	// registrations, and the dashboard its icons.
	"announce_token",
	"service",
	"service_icon",
	// People and their VPN devices with their keys: every phone keeps working.
	"person",
	"person_service",
	"vpn_device",
}

// transientTables only make sense on the machine they were written on.
// Their rows are removed from an export.
var transientTables = []string{
	"session",        // sign-ins of browsers; a restored SGC asks to sign in again
	"setup_token",    // the one-time setup link of that installation
	"service_health", // whether each service answered this device's probes
	"vpn_usage",      // what the VPN devices used (docs/design.md §10: not exported)
	"vpn_peer_state", // WireGuard's counters as this device last read them
	"notification",   // what this device reported in its page
	"person_session", // people signed in on this device's gate page
	"gate_pass",      // the gate's cookies this device gave out
}

// resetStatements put single-row tables back to their empty state instead of
// deleting the row, because SGC expects the row to exist.
var resetStatements = map[string]string{
	// What the last check for a newer version found; the restored SGC asks again.
	"update_check": `UPDATE update_check SET latest_version = '', notes = '', published_at = 0,
		checked_at = 0, error = '', error_at = 0`,
}

// transientSettings are keys in the setting table that are bookkeeping of
// one installation rather than settings.
var transientSettings = []string{
	"update.last_reported_id",     // which update outcome was already written to the audit log
	"firewall.open_change",        // a firewall change whose end is not in the audit log yet
	"ssh.open_change",             // an SSH change that waits for a login with a key
	"os_updates.open_install",     // an installation of Debian's updates whose end is not in the audit log yet
	"maintenance.last_restart",    // when SGC last restarted this device by itself
	"maintenance.last_update_try", // when SGC last tried to update itself by itself
	"update.first_seen",           // when this device first saw the newest version of SGC
	"adguard.restore_pending",     // an export was restored and its DNS part is not in place on this device yet
	"zone.check",                  // how this device's last question to Zone.eu ended
	"certificate.attempt",         // how this device's last attempt at a certificate went
	"certificate.open_records",    // DNS records an attempt at a certificate has made and not yet removed
	"certificate.renewal",         // when this device means to renew, and whether that failed
	"proxy.last_apply",            // how this device's last change to Traefik's configuration went
	"vpn.last_apply",              // how this device's last change to the VPN went
	"vpn.endpoint_state",          // what this device last saw of the home's public address
	"backups.last",                // how this device's last scheduled backup went
	"eol.state",                   // what this device last learnt about end-of-life dates
	"guide.state",                 // where the owner is in the guided setup; a restored device needs none
}

func cleanupStatements() []string {
	var statements []string
	for _, table := range transientTables {
		statements = append(statements, "DELETE FROM "+table)
	}
	for _, statement := range resetStatements {
		statements = append(statements, statement)
	}
	for _, key := range transientSettings {
		// Our own constants, not input: safe to put into the statement.
		statements = append(statements, "DELETE FROM setting WHERE key = '"+key+"'")
	}
	return statements
}
