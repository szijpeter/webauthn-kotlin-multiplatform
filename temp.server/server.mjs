import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const port = Number(process.env.PORT || 8787);
const rpId = process.env.RP_ID || 'localhost';
const rpName = process.env.RP_NAME || 'WebAuthn Kotlin MPP Temp Server';
const origin = process.env.ORIGIN || `https://${rpId}`;

const androidPackageName = process.env.ANDROID_PACKAGE_NAME || 'com.example.app';
const androidSha256 = process.env.ANDROID_SHA256 || 'PUT_DEBUG_OR_RELEASE_SHA256_HERE';
const iosAppId = process.env.IOS_APP_ID || 'TEAMID.com.example.app';

const registrationChallengeToUserId = new Map();
const authenticationChallengeToUserId = new Map();
const userCredentials = new Map();

function jsonResponse(statusCode, payload) {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'content-type',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
    },
    body: JSON.stringify(payload),
  };
}

function textResponse(statusCode, payload) {
  return {
    statusCode,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'content-type',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
    },
    body: payload,
  };
}

function encodeBase64Url(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, 'base64');
}

function randomChallenge() {
  return encodeBase64Url(randomBytes(32));
}

function normalizeOpaqueId(value) {
  return encodeBase64Url(Buffer.from(String(value), 'utf8'));
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(payload);
      } catch (error) {
        reject(new Error(`Invalid JSON body: ${error.message}`));
      }
    });
    request.on('error', reject);
  });
}

function parseClientDataChallenge(clientDataJsonB64Url) {
  if (!clientDataJsonB64Url) {
    return null;
  }
  try {
    const decoded = decodeBase64Url(clientDataJsonB64Url).toString('utf8');
    const parsed = JSON.parse(decoded);
    return typeof parsed.challenge === 'string' ? parsed.challenge : null;
  } catch {
    return null;
  }
}

function ensureUserCredentials(userId) {
  if (!userCredentials.has(userId)) {
    userCredentials.set(userId, []);
  }
  return userCredentials.get(userId);
}

export async function handleRequest(request) {
  const url = new URL(request.url || '/', `http://localhost:${port}`);

  if (request.method === 'OPTIONS') {
    return textResponse(204, '');
  }

  if (request.method === 'GET' && url.pathname === '/health') {
    return jsonResponse(200, { status: 'ok' });
  }

  if (request.method === 'GET' && url.pathname === '/.well-known/assetlinks.json') {
    return jsonResponse(200, [
      {
        relation: ['delegate_permission/common.get_login_creds'],
        target: {
          namespace: 'android_app',
          package_name: androidPackageName,
          sha256_cert_fingerprints: [androidSha256],
        },
      },
    ]);
  }

  if (
    request.method === 'GET' &&
    (url.pathname === '/.well-known/apple-app-site-association' || url.pathname === '/apple-app-site-association')
  ) {
    return jsonResponse(200, {
      applinks: {},
      webcredentials: {
        apps: [iosAppId],
      },
      appclips: {},
    });
  }

  if (request.method === 'GET' && url.pathname === '/') {
    return textResponse(
      200,
      [
        'Temporary WebAuthn server for client bring-up (development-only)',
        `RP_ID=${rpId}`,
        `ORIGIN=${origin}`,
        '',
        'Endpoints:',
        'POST /register/options',
        'POST /register/verify?userId=<id>',
        'POST /authenticate/options',
        'POST /authenticate/verify?challenge=<challenge>',
        'GET  /.well-known/assetlinks.json',
        'GET  /.well-known/apple-app-site-association',
      ].join('\n'),
    );
  }

  if (request.method === 'POST' && url.pathname === '/register/options') {
    const body = await readJsonBody(request);
    const requestedUserId = body.userId ? String(body.userId) : null;
    const userId = requestedUserId ? normalizeOpaqueId(requestedUserId) : encodeBase64Url(randomBytes(16));
    const userName = String(body.userName || requestedUserId || userId);
    const challenge = randomChallenge();

    registrationChallengeToUserId.set(challenge, userId);

    const existingCredentials = ensureUserCredentials(userId);
    const excludeCredentials = existingCredentials.map((credentialId) => ({
      type: 'public-key',
      id: credentialId,
      transports: ['internal'],
    }));

    return jsonResponse(200, {
      challenge,
      rp: {
        id: rpId,
        name: rpName,
      },
      user: {
        id: userId,
        name: userName,
        displayName: userName,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      timeout: 60000,
      excludeCredentials,
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      attestation: 'none',
    });
  }

  if (request.method === 'POST' && url.pathname === '/register/verify') {
    const body = await readJsonBody(request);
    const queryUserId = url.searchParams.get('userId');
    const normalizedQueryUserId = queryUserId ? normalizeOpaqueId(queryUserId) : null;
    const clientDataJson =
      body?.response?.clientDataJSON ??
      body?.response?.clientDataJson ??
      null;
    const clientDataChallenge = parseClientDataChallenge(clientDataJson);
    const mappedUserId = clientDataChallenge ? registrationChallengeToUserId.get(clientDataChallenge) : null;
    const userId = normalizedQueryUserId || mappedUserId || normalizeOpaqueId('default-user');

    if (clientDataChallenge) {
      registrationChallengeToUserId.delete(clientDataChallenge);
    }

    const bodyCredentialId = body.id || body.rawId;
    const credentialId = bodyCredentialId
      ? String(bodyCredentialId)
      : encodeBase64Url(randomBytes(16));
    const credentials = ensureUserCredentials(userId);
    if (!credentials.includes(credentialId)) {
      credentials.push(credentialId);
    }

    return jsonResponse(200, {
      success: true,
      userId,
      credentialId,
      note: 'Development-only verification: signature and attestation are not cryptographically verified.',
    });
  }

  if (request.method === 'POST' && url.pathname === '/authenticate/options') {
    const body = await readJsonBody(request);
    const userId = body.userId ? normalizeOpaqueId(String(body.userId)) : null;

    const allowCredentials = [];
    if (userId) {
      const credentials = ensureUserCredentials(userId);
      for (const credentialId of credentials) {
        allowCredentials.push({ type: 'public-key', id: credentialId, transports: ['internal'] });
      }
    }

    if (!userId) {
      for (const credentials of userCredentials.values()) {
        for (const credentialId of credentials) {
          allowCredentials.push({ type: 'public-key', id: credentialId, transports: ['internal'] });
        }
      }
    }

    const challenge = randomChallenge();
    authenticationChallengeToUserId.set(challenge, userId || 'anonymous');

    return jsonResponse(200, {
      challenge,
      rpId,
      timeout: 60000,
      userVerification: 'preferred',
      allowCredentials,
    });
  }

  if (request.method === 'POST' && url.pathname === '/authenticate/verify') {
    const body = await readJsonBody(request);
    const challenge = url.searchParams.get('challenge');

    if (!challenge || !authenticationChallengeToUserId.has(challenge)) {
      return jsonResponse(400, {
        success: false,
        message: 'Unknown or missing challenge',
      });
    }

    authenticationChallengeToUserId.delete(challenge);

    return jsonResponse(200, {
      success: true,
      credentialId: body?.id || body?.rawId || null,
      note: 'Development-only verification: signature is not cryptographically verified.',
    });
  }

  return jsonResponse(404, {
    success: false,
    message: `No route for ${request.method} ${url.pathname}`,
  });
}

export function resetState() {
  registrationChallengeToUserId.clear();
  authenticationChallengeToUserId.clear();
  userCredentials.clear();
}

const isEntrypoint = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntrypoint) {
  const server = createServer(async (request, response) => {
    try {
      const result = await handleRequest(request);
      response.writeHead(result.statusCode, result.headers);
      response.end(result.body);
    } catch (error) {
      response.writeHead(500, {
        'content-type': 'application/json; charset=utf-8',
        'access-control-allow-origin': '*',
      });
      response.end(
        JSON.stringify({
          success: false,
          message: error instanceof Error ? error.message : 'Internal server error',
        }),
      );
    }
  });

  server.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`temp.server listening on http://localhost:${port}`);
    // eslint-disable-next-line no-console
    console.log(`RP_ID=${rpId} ORIGIN=${origin}`);
  });
}
