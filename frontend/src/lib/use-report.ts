// Shared report generation flow:
// POST (generate) → poll GET /reports/{id} until completed/failed → download blob.

import { useCallback, useState } from 'react';
import { reportsApi } from '@/api/client';
import { useToast } from '@/components/ui/toast';
import type { Report } from '@/lib/types';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const POLL_INTERVAL_MS = 1200;
const POLL_TIMEOUT_MS = 90_000;

async function pollUntilDone(report: Report): Promise<Report> {
  let current = report;
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  while (
    (current.status === 'pending' || current.status === 'generating') &&
    Date.now() < deadline
  ) {
    await sleep(POLL_INTERVAL_MS);
    current = await reportsApi.get(current.id);
  }
  return current;
}

export function useReportGen() {
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  /** Runs a generator, polls to completion, then downloads. */
  const run = useCallback(
    async (generate: () => Promise<Report>, filename?: string): Promise<boolean> => {
      setBusy(true);
      try {
        toast.info('Report generation queued…');
        let report = await generate();
        report = await pollUntilDone(report);
        if (report.status === 'completed') {
          await reportsApi.download(report.id, filename);
          toast.success('Report ready — download started 📄');
          return true;
        }
        toast.error(report.error || `Report ${report.status}`);
        return false;
      } catch (e) {
        toast.error(e instanceof Error ? e.message : 'Report generation failed');
        return false;
      } finally {
        setBusy(false);
      }
    },
    [toast],
  );

  return { busy, run };
}
