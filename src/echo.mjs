export function analyzeClaims(claims, sources) {
  return claims.map(({ id, citations }) => ({
    id,
    citations: citations.map(({ source, quote, stance }) => {
      const bytes = Buffer.from(sources.get(source).text);
      const excerpt = Buffer.from(quote);
      const start = bytes.indexOf(excerpt);
      if (start < 0) return { source, status: 'missing' };
      if (bytes.indexOf(excerpt, start + 1) >= 0) return { source, status: 'ambiguous' };
      const match = { source, status: 'matched', start, end: start + excerpt.length };
      return stance ? { ...match, declaredStance: stance } : match;
    }),
  }));
}
