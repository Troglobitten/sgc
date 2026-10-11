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
}

// transientTables only make sense on the machine they were written on.
// Their rows are removed from an export.
var transientTables = []string{
	"session",     // sign-ins of browsers; a restored SGC asks to sign in again
	"setup_token", // the one-time setup link of that installation
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
	"update.last_reported_id", // which update outcome was already written to the audit log
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
