export function escapeHTML(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
export function filterFindings(findings, group, kind, confidence, query) {
  return findings.filter(f => (!group || f.group === group) && (!kind || f.kind === kind) && (!confidence || f.confidence === confidence) && (!query || `${f.group} ${f.location} ${f.target}`.toLowerCase().includes(query.toLowerCase())));
}
export function summarize(findings, selected) { const rows = findings.filter(f => selected.has(f.id)); return {count: rows.length, services: rows.filter(f => f.kind === 'Service').length, measuredBytes: rows.reduce((n,f) => n + (f.size ?? 0), 0), unmeasured: rows.filter(f=>f.size==null).length}; }

export function canExecutePlan(plan, busy, now=Date.now()) { return !busy && !!plan?.id && Number.isFinite(Date.parse(plan.expires)) && Date.parse(plan.expires)>now && Array.isArray(plan.items) && plan.items.length>0 && plan.items.every(i=>i.assessment?.eligibility==='ReversibleEligible'); }
export function operationSummary(operation) { const items=operation?.items??[];return {total:items.length,quarantined:items.filter(i=>i.state==='Quarantined').length,restored:items.filter(i=>i.state==='Restored').length,failed:items.filter(i=>i.state==='Failed').length,recovery:items.filter(i=>['Preparing','RestorePending','RecoveryRequired'].includes(i.state)).length}; }

export function eligibilityLabel(value) { return ({ReversibleEligible:"Eligible",ReportOnly:"Report only",Blocked:"Blocked"})[value]??"Report only"; }
