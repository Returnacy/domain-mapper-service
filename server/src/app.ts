import Fastify from 'fastify';
import fs from 'fs';
import path from 'path';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

type ServiceHosts = Record<string, string>;

type DomainMappingEntry = {
  label: string;
  brandId: string | null;
  businessId: string | null;
  services: ServiceHosts;
};

type HostInfo = {
  key: string;
  host: string;
  original: string;
  service: string | null;
  label: string;
  brandId: string | null;
  businessId: string | null;
};

type DomainMappingCache = {
  entries: DomainMappingEntry[];
  hostIndex: Record<string, HostInfo[]>;
};

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

function normalizeHostKey(value: string): { key: string; literal: string } {
  const trimmed = value.trim();
  if (!trimmed) return { key: '', literal: '' };
  const withoutScheme = trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  const hostSegment = withoutScheme.split('/')[0] ?? withoutScheme;
  const sanitized = hostSegment.trim();
  return { key: sanitized.toLowerCase(), literal: sanitized };
}

function parseMapping(raw: unknown): DomainMappingCache {
  const entries: DomainMappingEntry[] = [];
  const hostIndex: Record<string, HostInfo[]> = {};

  const iterable: Array<[string, any]> = Array.isArray(raw)
    ? raw.map((item, idx) => [String(item?.label ?? idx), item])
    : raw && typeof raw === 'object'
      ? Object.entries(raw as Record<string, any>)
      : [];

  for (const [key, value] of iterable) {
    if (!value || typeof value !== 'object') continue;
    const label = typeof value.label === 'string' && value.label.trim().length ? value.label.trim() : key;
    const brandId = value.brandId ?? null;
    const businessId = value.businessId ?? null;
    const services: ServiceHosts = {};

    for (const [serviceKey, serviceValue] of Object.entries(value)) {
      if (['brandId', 'businessId', 'label'].includes(serviceKey)) continue;
      if (typeof serviceValue !== 'string' || serviceValue.trim().length === 0) continue;
      const normalized = normalizeHostKey(serviceValue);
      if (!normalized.key) continue;
      services[serviceKey] = serviceValue.trim();
      const info: HostInfo = {
        key: normalized.key,
        host: normalized.literal,
        original: serviceValue.trim(),
        service: serviceKey,
        label,
        brandId: brandId ?? null,
        businessId: businessId ?? null,
      };
      if (!hostIndex[normalized.key]) hostIndex[normalized.key] = [];
      hostIndex[normalized.key].push(info);
    }

    entries.push({ label, brandId: brandId ?? null, businessId: businessId ?? null, services });
  }

  return { entries, hostIndex };
}

function loadMapping(): DomainMappingCache {
  const candidates: string[] = [];
  if (process.env.DOMAIN_MAPPING_FILE) candidates.push(process.env.DOMAIN_MAPPING_FILE);
  candidates.push(path.resolve(process.cwd(), 'domain-mapping.json'));
  const filePath = candidates.find(p => {
    try { return fs.existsSync(p); } catch { return false; }
  });
  if (!filePath) return { entries: [], hostIndex: {} };
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    return parseMapping(JSON.parse(raw));
  } catch (err) {
    app.log.error({ err }, 'domain-mapper: failed to parse domain mapping file');
    return { entries: [], hostIndex: {} };
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
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(host)) return host.replace(/\/+$/u, '');
  const sch = (scheme || process.env.BUSINESS_SERVICE_URL_SCHEME || 'https').toString();
  return `${sch}://${host}`;
}

function pickPreferredHost(entry: DomainMappingEntry): { host: string; service: string | null } | null {
  const priorities = ['business-service', 'api', 'backend', 'service'];
  for (const key of priorities) {
    const candidate = entry.services[key];
    if (candidate) return { host: candidate, service: key };
  }
  const firstKey = Object.keys(entry.services)[0];
  if (!firstKey) return null;
  return { host: entry.services[firstKey], service: firstKey };
}

const mappingCache = loadMapping();
app.log.info({ entries: mappingCache.entries.length }, 'domain-mapper: loaded domain mappings');

app.get('/health', async () => ({ status: 'ok' }));

// Resolve mapping by host
app.get('/api/v1/resolve', async (request, reply) => {
  const q = request.query as any;
  const rawHost = (q.host as string | undefined) || '';
  const normalized = normalizeHostKey(rawHost);
  if (!normalized.key) return reply.code(400).send({ error: 'host required' });
  const infos = mappingCache.hostIndex[normalized.key];
  if (!infos || infos.length === 0) return reply.code(404).send({ error: 'NOT_FOUND' });
  const info = infos[0];
  return {
    host: info.host,
    originalHost: info.original,
    service: info.service,
    label: info.label,
    brandId: info.brandId,
    businessId: info.businessId,
    url: deriveUrlFromHost(info.original || info.host),
  };
});

// Reverse lookup: given businessId return preferred host and info
app.get('/api/v1/business/:businessId', async (request, reply) => {
  const { businessId } = request.params as any;
  if (!businessId) return reply.code(400).send({ error: 'businessId required' });
  const entries = mappingCache.entries.filter(entry => entry.businessId === businessId);
  if (entries.length === 0) return reply.code(404).send({ error: 'NOT_FOUND' });

  const candidates: Array<{ host: string; service: string | null; label: string }> = [];
  for (const entry of entries) {
    const preferred = pickPreferredHost(entry);
    if (preferred) {
      candidates.push({ host: preferred.host, service: preferred.service, label: entry.label });
    }
    for (const [serviceKey, host] of Object.entries(entry.services)) {
      candidates.push({ host, service: serviceKey, label: entry.label });
    }
  }

  if (candidates.length === 0) return reply.code(404).send({ error: 'NOT_FOUND' });

  const ranked = candidates
    .map(candidate => ({ candidate, score: scoreHostPreference(candidate.host) }))
    .sort((a, b) => b.score - a.score);

  const best = ranked[0].candidate;
  return {
    host: best.host,
    service: best.service,
    url: deriveUrlFromHost(best.host),
    businessId,
    brandId: entries[0].brandId,
    label: entries[0].label,
  };
});

// List all mappings
app.get('/api/v1/businesses', async () => {
  return mappingCache.entries.map(entry => ({
    label: entry.label,
    brandId: entry.brandId,
    businessId: entry.businessId,
    services: entry.services,
  }));
});

const port = Number(process.env.PORT || 4005);
app
  .listen({ port, host: '0.0.0.0' })
  .then(() => app.log.info(`domain-mapper-service listening on ${port}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
