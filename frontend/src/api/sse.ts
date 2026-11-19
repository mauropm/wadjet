// EventSource wrapper for GET /api/v1/events with exponential-backoff
// reconnect. Subscribes to topics per the CONTRACTS.md SSE wire contract:
//
//   event: scan.status      data: {session_id, status, error?}
//   event: scan.progress    data: {session_id, assets_processed, findings_created, findings_updated}
//   event: execution.status data: {session_id, execution_id, scanner, status, assets_observed, findings_found, error?}
//   event: report.status    data: {report_id, project_id, status, file_size}
//
// The contract table also hints the `event:` field may be a bare prefix
// ("scan", "report") with `kind` inside the payload. We listen on BOTH the
// full topic names and their prefixes, and normalize: the emitted topic is
// `data.kind` when it looks like a kind, otherwise the event name.

const EVENTS_URL = '/api/v1/events';
const BASE_DELAY_MS = 500;
const MAX_DELAY_MS = 30_000;

export type SSEHandler = (topic: string, data: Record<string, unknown>) => void;

export interface Subscription {
  close(): void;
}

function eventNames(topics: string[]): string[] {
  const names = new Set<string>();
  for (const t of topics) {
    names.add(t);
    const dot = t.indexOf('.');
    if (dot > 0) names.add(t.slice(0, dot)); // e.g. "scan.status" → also "scan"
  }
  names.add('message'); // unnamed events (data-only)
  return [...names];
}

function normalize(event: string, raw: unknown, wanted: Set<string>): [string, Record<string, unknown>] | null {
  if (raw === null || typeof raw !== 'object') return null;
  const data = raw as Record<string, unknown>;
  const kind = typeof data.kind === 'string' ? data.kind : null;
  const topic = kind ?? event;
  if (!wanted.has(topic) && !wanted.has(event)) return null;
  return [topic, data];
}

/**
 * Subscribe to SSE topics. Returns a handle whose close() unsubscribes and
 * stops reconnect attempts. Reconnect uses exponential backoff with jitter
 * and resets after a successful open.
 */
export function subscribe(topics: string[], handler: SSEHandler): Subscription {
  const wanted = new Set(topics);
  let es: EventSource | null = null;
  let attempt = 0;
  let closed = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const connect = () => {
    if (closed) return;
    es = new EventSource(EVENTS_URL, { withCredentials: true });

    es.onopen = () => {
      attempt = 0;
    };

    for (const name of eventNames(topics)) {
      es.addEventListener(name, (ev: MessageEvent) => {
        let parsed: unknown = null;
        try {
          parsed = JSON.parse(ev.data as string);
        } catch {
          return;
        }
        const n = normalize((ev as Event).type, parsed, wanted);
        if (n) handler(n[0], n[1]);
      });
    }

    es.onerror = () => {
      if (closed) return;
      es?.close();
      es = null;
      const delay = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** attempt);
      attempt += 1;
      const jitter = delay * (0.75 + Math.random() * 0.5);
      timer = setTimeout(connect, jitter);
    };
  };

  connect();

  return {
    close() {
      closed = true;
      if (timer !== null) clearTimeout(timer);
      es?.close();
      es = null;
    },
  };
}

/**
 * Convenience hook helper: is this event addressed at the given scan session
 * (or broadcast without a session id)?
 */
export function forSession(data: Record<string, unknown>, sessionId: string): boolean {
  return data.session_id == null || data.session_id === sessionId;
}
