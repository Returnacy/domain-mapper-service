import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

type DomainInfo = { brandId: string | null; businessId?: string | null };

const app = Fastify({ logger: true });

// Optional JWT validation using Keycloak JWKs when ENFORCE_AUTH=true
const enforceAuth = String(process.env.ENFORCE_AUTH || 'true').toLowerCase() !== 'false';
const issuerEnv = process.env.OIDC_ISSUER
  || ((process.env.KEYCLOAK_BASE_URL && process.env.KEYCLOAK_REALM)
    ? `${process.env.KEYCLOAK_BASE_URL}/realms/${process.env.KEYCLOAK_REALM}`
    : undefined);
const audienceEnv = (process.env.KEYCLOAK_AUDIENCE || '').trim();
const allowedClients = (process.env.ALLOWED_CLIENT_IDS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
if (enforceAuth && issuerEnv) {
  try {
    const jwksUrl = new URL(`${issuerEnv}/protocol/openid-connect/certs`);
    jwks = createRemoteJWKSet(jwksUrl);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn('domain-mapper: failed to initialize JWKS', e);
  }
}

app.addHook('onRequest', async (request, reply) => {
  if (request.url.startsWith('/health')) return;
  if (!enforceAuth) return;

  const auth = (request.headers['authorization'] || request.headers['Authorization' as any]) as string | undefined;
  if (!auth || typeof auth !== 'string' || !auth.toLowerCase().startsWith('bearer ')) {
    return reply.code(401).send({ error: 'UNAUTHORIZED' });
  }

  const token = auth.slice(7).trim();

  // If JWKS is not configured, fall back to header presence check
  if (!jwks || !issuerEnv) return;

  try {
    const verifyOpts: Record<string, any> = { issuer: issuerEnv };
    if (audienceEnv) verifyOpts.audience = audienceEnv.split(',').map(s => s.trim()).filter(Boolean);
    const { payload } = await jwtVerify(token, jwks, verifyOpts);

    // Optional allow-list of client ids (for client-credential tokens 'azp' is the client id)
    if (allowedClients.length > 0) {
      const clientId = (payload as JWTPayload & { azp?: string; clientId?: string }).azp
        || (payload as any).clientId
        || (payload as any).client_id;
      if (!clientId || !allowedClients.includes(String(clientId))) {
        return reply.code(403).send({ error: 'FORBIDDEN_CLIENT' });
      }
    }
  } catch (err) {
    request.log.warn({ err }, 'JWT verification failed');
    return reply.code(401).send({ error: 'UNAUTHORIZED' });
  }
});

function loadMapping(): Record<string, DomainInfo> {
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
  const info = (map as any)[host] as DomainInfo | undefined;
  if (!info) return reply.code(404).send({ error: 'NOT_FOUND' });
  return { host, ...info };
});

// Reverse lookup: given businessId return preferred host and info
app.get('/api/v1/business/:businessId', async (request, reply) => {
  const { businessId } = request.params as any;
  if (!businessId) return reply.code(400).send({ error: 'businessId required' });
  const map = loadMapping();
  const entries = Object.entries(map).filter(([_, v]) => (v as DomainInfo | undefined)?.businessId === businessId);
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
