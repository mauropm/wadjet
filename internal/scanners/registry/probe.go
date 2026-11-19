package registry

import (
	"context"
	"fmt"
	"os/exec"
)

// runVersionProbe executes `executable --version` strictly through
// exec.CommandContext with a fixed argument list. Overridable in tests.
var runVersionProbe = func(ctx context.Context, executable string) (string, error) {
	cmd := exec.CommandContext(ctx, executable, "--version")
	cmd.WaitDelay = availabilityTimeout
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("version probe for %s: %w", executable, ctx.Err())
	}
	if err != nil {
		return string(out), fmt.Errorf("version probe for %s failed: %w", executable, err)
	}
	return string(out), nil
}
