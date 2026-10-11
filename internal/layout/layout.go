// Package layout names where SGC keeps things on the gateway.
//
// It contains only constants and imports nothing, so every program can use
// it without pulling in code it has no business carrying. In particular the
// root helper needs to know the database's file name to back it up, but must
// not link the database engine for that.
package layout

const (
	// InstallRoot holds one folder per installed release under releases/,
	// and "current", a link to the one in use.
	InstallRoot = "/opt/sgc"

	// StateDir belongs to the unprivileged service user.
	StateDir = "/var/lib/sgc"
	// DatabaseFile is the database's name inside StateDir.
	DatabaseFile = "sgc.db"
	// SpoolFolder, inside StateDir, is where a downloaded release waits for
	// the root updater.
	SpoolFolder = "updates"

	// UpdateWorkDir belongs to root: the updater's status (which the web
	// process reads) and its database backup.
	UpdateWorkDir = "/var/lib/sgc-update"

	// UnitDir is where systemd looks for SGC's unit files.
	UnitDir = "/etc/systemd/system"

	// HelperSocket is created by systemd (sgc-helper.socket).
	HelperSocket = "/run/sgc-helper/helper.sock"

	// WebPort is where the UI listens until SGC has its own hostname and a
	// real certificate.
	WebPort = 8443

	// ServiceUser runs the web process.
	ServiceUser = "sgc"
)
