import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';

const app = Fastify({ logger: true });

// Simple allow-list guard: require Authorization header for non-health endpoints if ENFORCE_AUTH=true
app.addHook('onRequest', async (request, reply) => {
  if (request.url.startsWith('/health')) return;
  const enforce = String(process.env.ENFORCE_AUTH || 'true').toLowerCase() !== 'false';
  if (enforce) {
    const auth = request.headers['authorization'] || request.headers['Authorization' as any];
    if (!auth || typeof auth !== 'string' || !auth.toLowerCase().startsWith('bearer ')) {
      reply.code(403).send({ error: 'FORBIDDEN' });
    }
  }
});

function loadMapping(): Record<string, { brandId: string | null; businessId: string }> {
  // Load from env override or common locations
  const candidates: string[] = [];
  if (process.env.DOMAIN_MAPPING_FILE) candidates.push(process.env.DOMAIN_MAPPING_FILE);
  candidates.push(path.resolve(process.cwd(), 'domain-mapping.json'));
  const filePath = candidates.find(p => {
    try { return fs.existsSync(p); } catch { return false; }
  });
  if (!filePath) return {} as any;
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {} as any;
  }
}

function scoreHostPreference(value: string): number {
  const lower = value.toLowerCase();
  let score = 0;
  if (lower.includes('business')) score += 5;
  if (lower.includes('api')) score += 3;
  if (lower.includes('service')) score += 2;
  if (lower.includes('backend')) score += 1;
  if (lower.includes('localhost')) score -= 1;
  return score;
}

function deriveUrlFromHost(host: string, scheme?: string): string {
  if (!host) return '';
  if (host.startsWith('http://') || host.startsWith('https://')) return host;
  const sch = (scheme || process.env.BUSINESS_SERVICE_URL_SCHEME || 'https').toString();
  return `${sch}://${host}`;
}

app.get('/health', async () => ({ status: 'ok' }));

// Resolve mapping by host
app.get('/api/v1/resolve', async (request, reply) => {
  const q = request.query as any;
  const rawHost = (q.host as string | undefined) || '';
  const host = rawHost.toLowerCase().split(':')[0];
  if (!host) return reply.code(400).send({ error: 'host required' });
  const map = loadMapping();
  const info = (map as any)[host];
  if (!info) return reply.code(404).send({ error: 'NOT_FOUND' });
  return { host, ...info };
});

// Reverse lookup: given businessId return preferred host and info
app.get('/api/v1/business/:businessId', async (request, reply) => {
  const { businessId } = request.params as any;
  if (!businessId) return reply.code(400).send({ error: 'businessId required' });
  const map = loadMapping();
  const entries = Object.entries(map).filter(([_, v]) => (v as any)?.businessId === businessId);
  if (entries.length === 0) return reply.code(404).send({ error: 'NOT_FOUND' });
  const ranked = entries
    .map(([host, v]) => ({ host, v, score: scoreHostPreference(host) }))
    .sort((a, b) => b.score - a.score);
  const best = ranked[0];
  return {
    host: best.host,
    url: deriveUrlFromHost(best.host),
    businessId: (best.v as any).businessId,
    brandId: (best.v as any).brandId ?? null,
  };
});

// List all mappings
app.get('/api/v1/businesses', async () => {
  const map = loadMapping();
  return Object.entries(map).map(([host, v]) => ({ host, ...(v as any), url: deriveUrlFromHost(host) }));
});

const port = Number(process.env.PORT || 4005);
app
  .listen({ port, host: '0.0.0.0' })
  .then(() => app.log.info(`domain-mapper-service listening on ${port}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
