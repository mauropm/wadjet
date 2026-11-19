import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { SeverityChip, StatusChip } from './chips';
import { Button } from './ui/button';

describe('SeverityChip', () => {
  it('renders emoji, label and severity color class', () => {
    const html = renderToStaticMarkup(<SeverityChip severity="critical" />);
    expect(html).toContain('🔴');
    expect(html).toContain('Critical');
    expect(html).toContain('sev-critical');
  });

  it('shows CVSS score with one decimal when provided', () => {
    const html = renderToStaticMarkup(<SeverityChip severity="high" showScore={8.75} />);
    expect(html).toContain('8.8'); // rounded to 1 decimal
  });

  it('degrades for unknown severity instead of throwing', () => {
    const html = renderToStaticMarkup(<SeverityChip severity="who_knows" />);
    expect(html).toContain('who_knows');
  });
});

describe('StatusChip', () => {
  it('renders a running scan as live-labeled', () => {
    const html = renderToStaticMarkup(<StatusChip status="running" kind="scan" />);
    expect(html).toContain('Running');
    expect(html).toContain('animate-pulse-dot');
  });

  it('renders finding statuses via the central map', () => {
    expect(renderToStaticMarkup(<StatusChip status="false_positive" kind="finding" />)).toContain(
      'False Positive',
    );
    expect(renderToStaticMarkup(<StatusChip status="accepted_risk" kind="finding" />)).toContain(
      'Accepted Risk',
    );
  });
});

describe('Button', () => {
  it('disables and shows a spinner while loading', () => {
    const html = renderToStaticMarkup(
      <Button variant="primary" loading>
        Go
      </Button>,
    );
    expect(html).toContain('disabled');
    expect(html).toContain('animate-spin');
    expect(html).toContain('bg-accent');
  });
});
