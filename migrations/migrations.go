// Package migrations embeds the SQL migration files. The database package
// applies them in filename order. Keeping the SQL here (rather than under
// internal/database) preserves the conventional top-level migrations/
// directory while satisfying Go's embed locality rule.
package migrations

import "embed"

// FS contains all *.sql migration files.
//
//go:embed *.sql
var FS embed.FS
