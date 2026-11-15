const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[char]));

function table(headings, rows) {
  return '<div class="scroll"><table><thead><tr>'
    + headings.map(value => '<th scope="col">' + value + '</th>').join('')
    + '</tr></thead><tbody>'
    + rows.map(row => '<tr>' + row.map(value => '<td>' + escapeHtml(value) + '</td>').join('') + '</tr>').join('')
    + '</tbody></table></div>';
}

function inspection(report) {
  const reviews = new Map(report.jester.map(review => [review.id, review]));
  const claims = report.echo.map(({ id, citations }) => {
    const review = reviews.get(id);
    const matches = citations.map(item => {
      const offset = item.status === 'matched' ? ' (bytes ' + item.start + '–' + item.end + ')' : '';
      const stance = item.declaredStance ? ' · declared ' + item.declaredStance : '';
      return item.source + ' · ' + item.status + offset + stance;
    });
    return [id, matches.join('\n') || 'No citations', review.declaredOrigins, review.flags.join('\n') || 'None'];
  });
  return '<section><h2>Evidence</h2><p class="digest">Packet SHA-256 <code>'
    + escapeHtml(report.packetDigest) + '</code></p>'
    + table(['Source', 'SHA-256'], report.evidence.map(({ id, digest }) => [id, digest]))
    + '</section><section><h2>Claim review</h2>'
    + table(['Claim', 'Echo 777 citations', 'Declared origins', 'Jester findings'], claims)
    + '<p>Citation matches show where text appears. Origin labels are supplied by the investigator.</p></section>';
}

function renderCase(report) {
  const passed = report.sentinel.status === 'passed';
  const status = passed ? 'Sentinel passed integrity checks' : 'Sentinel blocked inspection';
  const advisories = report.sentinel.advisories ?? [];
  const advisoryTable = advisories.length
    ? '<h3>Evidence advisories</h3>' + table(['Source', 'Finding'],
      advisories.map(({ source, code }) => [source, code]))
    : '';
  const details = passed ? inspection(report) : '<ul>'
    + report.sentinel.findings.map(finding => '<li><code>' + escapeHtml(finding) + '</code></li>').join('')
    + '</ul>';
  const title = report.id ? '<h2>Case ' + escapeHtml(report.id) + '</h2>' : '';
  return title + '<section><h2 class="' + (passed ? 'passed' : 'blocked') + '">'
    + status + '</h2>' + (passed ? advisoryTable : details) + '</section>'
    + (passed ? details : '');
}

export function renderMissionControl(report) {
  const reports = Array.isArray(report) ? report : [report];
  const blocked = reports.filter(item => item.sentinel.status === 'blocked').length;
  const summary = Array.isArray(report)
    ? '<p>' + reports.length + ' cases · ' + blocked + ' blocked</p>'
    : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>RichardLab Mission Control</title>
<style>
:root { color-scheme: dark; font: 16px/1.55 "Geist", "Segoe UI", sans-serif; background: #101822; color: #edf4fa; }
body { margin: 0; }
main { width: min(72rem, calc(100% - 2rem)); margin: 3rem auto; }
header { border-bottom: 1px solid #415367; padding-bottom: 1rem; }
h1 { margin: .15rem 0; font-size: clamp(2rem, 6vw, 3.25rem); }
h2 { margin-top: 0; font-size: 1.2rem; }
section { margin-top: 1rem; padding: 1.25rem; background: #182432; border: 1px solid #415367; border-radius: .65rem; }
p { color: #c2d1df; }
.passed { color: #85e8bf; }
.blocked { color: #ffb4a9; }
.digest, code, td { overflow-wrap: anywhere; }
.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; text-align: left; }
th, td { border-bottom: 1px solid #415367; padding: .65rem; vertical-align: top; }
td { white-space: pre-line; }
th { color: #a9c9eb; }
</style>
</head>
<body><main>
<header><p>RichardLab 2.0</p><h1>Mission Control</h1></header>
${summary}
${reports.map(item => '<article>' + renderCase(item) + '</article>').join('\n')}
</main></body>
</html>
`;
}
