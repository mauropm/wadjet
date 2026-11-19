import { describe, expect, it } from 'vitest';
import {
  FINDING_STATUSES,
  SEVERITIES,
  assetTypeLabel,
  findingStatusMeta,
  isSeverity,
  scanStatusMeta,
  severityMeta,
  severityWeight,
} from './severity';

describe('severityMeta', () => {
  it('maps all five severities with brand colors and emoji', () => {
    expect(severityMeta('critical').hex).toBe('#EF4444');
    expect(severityMeta('high').hex).toBe('#F97316');
    expect(severityMeta('medium').hex).toBe('#EAB308');
    expect(severityMeta('low').hex).toBe('#3B82F6');
    expect(severityMeta('info').hex).toBe('#64748B');

    expect(severityMeta('critical').emoji).toBe('🔴');
    expect(severityMeta('high').emoji).toBe('🟠');
    expect(severityMeta('medium').emoji).toBe('🟡');
    expect(severityMeta('low').emoji).toBe('🔵');
    expect(severityMeta('info').emoji).toBe('⚪');
  });

  it('is case-insensitive', () => {
    expect(severityMeta('CRITICAL').label).toBe('Critical');
    expect(severityMeta('High').label).toBe('High');
  });

  it('orders by weight: critical > high > medium > low > info', () => {
    const weights = SEVERITIES.map(severityWeight);
    const sorted = [...weights].sort((a, b) => b - a);
    expect(weights).toEqual(sorted);
    expect(severityWeight('critical')).toBeGreaterThan(severityWeight('high'));
    expect(severityWeight('info')).toBeGreaterThan(severityWeight('nonexistent'));
  });

  it('degrades gracefully for unknown / null severity', () => {
    const unknown = severityMeta('apocalyptic');
    expect(unknown.label).toBe('apocalyptic');
    expect(unknown.weight).toBe(0);
    expect(severityMeta(null).label).toBe('Unknown');
    expect(severityMeta(undefined).emoji).toBe('⚪');
  });

  it('chip classes always include a border for readability', () => {
    for (const sev of SEVERITIES) {
      expect(severityMeta(sev).chip).toContain('border');
      expect(severityMeta(sev).chip).toMatch(/text-/);
    }
  });
});

describe('status metadata', () => {
  it('covers every finding status from models.go', () => {
    for (const s of FINDING_STATUSES) {
      const m = findingStatusMeta(s);
      expect(m.label).not.toBe('Unknown');
      expect(m.chip).toMatch(/border/);
    }
    expect(findingStatusMeta('accepted_risk').label).toBe('Accepted Risk');
    expect(findingStatusMeta('ghost_mode').label).toBe('ghost_mode');
  });

  it('handles scan statuses including completed_with_errors', () => {
    expect(scanStatusMeta('completed_with_errors').label).toBe('Completed w/ errors');
    expect(scanStatusMeta('running').label).toBe('Running');
    expect(scanStatusMeta('draft').label).toBe('Draft');
  });

  it('isSeverity guards type narrowing', () => {
    expect(isSeverity('low')).toBe(true);
    expect(isSeverity('LOW')).toBe(true);
    expect(isSeverity('urgent')).toBe(false);
    expect(isSeverity(null)).toBe(false);
  });

  it('asset type labels match models.go constants', () => {
    expect(assetTypeLabel('web_app')).toBe('Web App');
    expect(assetTypeLabel('ipv4')).toBe('IPv4');
    expect(assetTypeLabel('mystery')).toBe('mystery');
  });
});
