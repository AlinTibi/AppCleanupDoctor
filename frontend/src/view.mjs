export function escapeHTML(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
export function filterFindings(findings, group, kind, confidence, query) {
  return findings.filter(f => (!group || f.group === group) && (!kind || f.kind === kind) && (!confidence || f.confidence === confidence) && (!query || `${f.group} ${f.location} ${f.target}`.toLowerCase().includes(query.toLowerCase())));
}
export function summarize(findings, selected) { const rows = findings.filter(f => selected.has(f.id)); return {count: rows.length, services: rows.filter(f => f.kind === 'Service').length, measuredBytes: rows.reduce((n,f) => n + (f.size ?? 0), 0), unmeasured: rows.filter(f=>f.size==null).length}; }
