const controls = [
  'treatsEvidenceAsUntrusted',
  'restrictsToolAccess',
  'permitsExternalWrites',
  'requiresHumanApprovalForWrites',
  'sendsRawEvidenceToProvider',
];

export function reviewAiControls(bytes) {
  const snapshot = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)
      || Object.keys(snapshot).length !== controls.length
      || !controls.every(key => Object.hasOwn(snapshot, key) && typeof snapshot[key] === 'boolean')) {
    throw new Error('Invalid AI control snapshot');
  }
  const findings = [];
  if (!snapshot.treatsEvidenceAsUntrusted) findings.push('evidence-instruction-boundary-missing');
  if (!snapshot.restrictsToolAccess) findings.push('tool-access-unrestricted');
  if (snapshot.permitsExternalWrites && !snapshot.requiresHumanApprovalForWrites) {
    findings.push('external-writes-without-human-approval');
  }
  if (snapshot.sendsRawEvidenceToProvider) findings.push('raw-evidence-leaves-local-environment');
  return { findings };
}
