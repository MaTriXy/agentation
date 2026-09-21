import type { IncomingMessage, ServerResponse } from "node:http";

export function createCorsPolicy(value = process.env.AGENTATION_CORS_ORIGINS) {
  const entries = value === undefined ? ['*'] : value.split(',').map(s => s.trim()).filter(Boolean);
  const wildcard = entries.length === 1 && entries[0] === '*';
  const origins = new Set<string>();
  if (!wildcard) {
    for (const entry of entries) {
      try {
        const url = new URL(entry);
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
            url.pathname !== '/' || url.search || url.hash) throw new Error();
        origins.add(url.origin);
      } catch {
        throw new Error('AGENTATION_CORS_ORIGINS must be a comma-separated list of HTTP(S) origins, or * by itself. Regex patterns are not supported.');
      }
    }
  }

  // Run once at the request boundary, before routing, mutations or cloud proxying.
  return (req: IncomingMessage, res: ServerResponse): boolean => {
    const origin = req.headers.origin;
    if (!wildcard) res.setHeader('Vary', 'Origin');
    if (!wildcard && origin !== undefined && !origins.has(origin)) return false;
    if (wildcard || origin) res.setHeader('Access-Control-Allow-Origin', wildcard ? '*' : origin!);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID');
    res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
    return true;
  };
}
