export function reviewClaims(claims, sources) {
  return claims.map(({ id, citations }) => {
    const matched = [...new Set(citations.filter(item => item.status === 'matched')
      .map(item => item.source))].map(source => sources.get(source));
    const declaredOrigins = new Set(matched.map(source => source.origin)).size;
    const flags = [];
    if (!matched.length) flags.push('no-matched-citations');
    if (citations.some(item => item.status !== 'matched')) flags.push('unresolved-citations');
    if (matched.length && declaredOrigins === 1) flags.push('single-declared-origin');
    if (new Set(matched.map(source => source.digest)).size < matched.length) {
      flags.push('identical-source-bytes');
    }
    const stances = new Set(citations.map(item => item.declaredStance));
    if (stances.has('challenges')) {
      flags.push(stances.has('supports') ? 'conflicting-declared-stances' : 'matched-challenging-citation');
    }
    return { id, declaredOrigins, flags };
  });
}
