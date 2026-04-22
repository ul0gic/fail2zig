/**
 * Minimal Prometheus text-exposition parser for the see-it-live
 * dashboard.
 *
 * fail2zig's `/metrics` endpoint emits unlabeled counters and
 * gauges — `fail2zig_lines_parsed`, `fail2zig_bans_total`,
 * `process_resident_memory_bytes`, etc. — plus the usual `# HELP`
 * and `# TYPE` prelude.  We don't need a full PromQL-compliant
 * parser; we need "give me the number for a named metric."
 *
 * Input:  raw text body from fetch("/metrics").text().
 * Output: a sample with counters + gauges as Maps.  Maps (not plain
 * objects) keep `security/detect-object-injection` happy when the
 * key is user-supplied — here the key comes from the HTTP response
 * body, so treating it as attacker-controlled is the right posture.
 *
 * Unknown TYPE lines default to `counters` (closest match for
 * Prometheus's monotonic default) — good enough for the six metrics
 * the MetricsPane cares about.  Labels are ignored in v1 since all
 * fail2zig metrics are unlabeled.
 */

export interface PrometheusSample {
  readonly counters: ReadonlyMap<string, number>;
  readonly gauges: ReadonlyMap<string, number>;
}

type MetricType = 'counter' | 'gauge';

/** Strips labels.  `foo{a="b",c="d"}` → `foo`. */
function stripLabels(nameWithLabels: string): string {
  const brace = nameWithLabels.indexOf('{');
  return brace === -1 ? nameWithLabels : nameWithLabels.slice(0, brace);
}

export function parsePrometheus(text: string): PrometheusSample {
  const typeMap = new Map<string, MetricType>();
  const counters = new Map<string, number>();
  const gauges = new Map<string, number>();

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (line.length === 0) continue;

    if (line.startsWith('# TYPE ')) {
      const parts = line.slice(7).split(/\s+/);
      const name = parts[0];
      const kind = parts[1];
      if (typeof name === 'string' && (kind === 'counter' || kind === 'gauge')) {
        typeMap.set(name, kind);
      }
      continue;
    }
    if (line.startsWith('#')) continue;

    // Sample: `<metric>[{labels}] <value> [<timestamp>]`.
    const spaceIdx = line.indexOf(' ');
    if (spaceIdx === -1) continue;
    const nameWithLabels = line.slice(0, spaceIdx);
    const valueStr = line.slice(spaceIdx + 1).trim().split(/\s+/)[0];
    if (valueStr === undefined) continue;
    const value = Number(valueStr);
    if (!Number.isFinite(value)) continue;

    const name = stripLabels(nameWithLabels);
    const kind = typeMap.get(name) ?? 'counter';
    if (kind === 'gauge') {
      gauges.set(name, value);
    } else {
      counters.set(name, value);
    }
  }

  return { counters, gauges };
}

/** Convenience: look up a metric regardless of counter/gauge bucket. */
export function metricValue(sample: PrometheusSample, name: string): number | null {
  const c = sample.counters.get(name);
  if (typeof c === 'number') return c;
  const g = sample.gauges.get(name);
  if (typeof g === 'number') return g;
  return null;
}
