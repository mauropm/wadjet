package findings

import (
	"testing"

	"github.com/mauropm/wadjet/internal/assets/itest"
)

// TestMain opens one isolated database and applies the schema once per run.
func TestMain(m *testing.M) { itest.Main(m, "findings") }
