import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { handleRequest, resetState } from './server.mjs';

function createJsonRequest(method, path, body) {
  const request = new EventEmitter();
  request.method = method;
  request.url = path;

  queueMicrotask(() => {
    if (body != null) {
      request.emit('data', Buffer.from(JSON.stringify(body), 'utf8'));
    }
    request.emit('end');
  });

  return request;
}

function parseJsonBody(response) {
  return JSON.parse(response.body);
}

test('authentication options return known credential ids for user', async () => {
  resetState();

  const credentialId = 'MzMzMzMzMzMzMzMzMzMzMw';

  const registerOptionsResponse = await handleRequest(
    createJsonRequest('POST', '/register/options', {
      userId: 'AQID',
      userName: 'alice@example.com',
    }),
  );
  assert.equal(registerOptionsResponse.statusCode, 200);

  const registerVerifyResponse = await handleRequest(
    createJsonRequest('POST', '/register/verify?userId=AQID', {
      id: credentialId,
      rawId: credentialId,
      response: {
        clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZm9vIn0',
      },
    }),
  );
  assert.equal(registerVerifyResponse.statusCode, 200);

  const authOptionsResponse = await handleRequest(
    createJsonRequest('POST', '/authenticate/options', {
      userId: 'AQID',
    }),
  );
  assert.equal(authOptionsResponse.statusCode, 200);

  const authOptions = parseJsonBody(authOptionsResponse);
  assert.ok(Array.isArray(authOptions.allowCredentials));
  assert.equal(authOptions.allowCredentials.length, 1);
  assert.equal(authOptions.allowCredentials[0].id, credentialId);
});

test('registration options stay repeatable for same user', async () => {
  resetState();

  const firstOptions = await handleRequest(
    createJsonRequest('POST', '/register/options', {
      userId: 'AQID',
      userName: 'alice@example.com',
    }),
  );
  assert.equal(firstOptions.statusCode, 200);

  await handleRequest(
    createJsonRequest('POST', '/register/verify?userId=AQID', {
      id: 'MzMzMzMzMzMzMzMzMzMzMw',
      rawId: 'MzMzMzMzMzMzMzMzMzMzMw',
      response: {
        clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZm9vIn0',
      },
    }),
  );

  const secondOptions = await handleRequest(
    createJsonRequest('POST', '/register/options', {
      userId: 'AQID',
      userName: 'alice@example.com',
    }),
  );
  assert.equal(secondOptions.statusCode, 200);

  const payload = parseJsonBody(secondOptions);
  assert.ok(Array.isArray(payload.excludeCredentials));
  assert.equal(payload.excludeCredentials.length, 0);
});

test('registration verify prefers rawId and auth fallback returns global credentials', async () => {
  resetState();

  const registerOptionsResponse = await handleRequest(
    createJsonRequest('POST', '/register/options', {
      userId: 'AQID',
      userName: 'alice@example.com',
    }),
  );
  assert.equal(registerOptionsResponse.statusCode, 200);

  await handleRequest(
    createJsonRequest('POST', '/register/verify?userId=AQID', {
      id: 'idValueOnly',
      rawId: 'rawIdValue',
      response: {
        clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZm9vIn0',
      },
    }),
  );

  const unknownUserAuthResponse = await handleRequest(
    createJsonRequest('POST', '/authenticate/options', {
      userId: 'UNKNOWN',
    }),
  );
  assert.equal(unknownUserAuthResponse.statusCode, 200);
  const payload = parseJsonBody(unknownUserAuthResponse);
  assert.ok(Array.isArray(payload.allowCredentials));
  assert.equal(payload.allowCredentials.length, 2);
  assert.ok(payload.allowCredentials.some((it) => it.id === 'rawIdValue'));
  assert.ok(payload.allowCredentials.some((it) => it.id === 'idValueOnly'));
});

test('assetlinks includes URL handling and passkey relations', async () => {
  const response = await handleRequest(
    createJsonRequest('GET', '/.well-known/assetlinks.json'),
  );

  assert.equal(response.statusCode, 200);

  const payload = parseJsonBody(response);
  assert.ok(Array.isArray(payload));
  assert.equal(payload.length, 1);

  const relations = payload[0]?.relation;
  assert.ok(Array.isArray(relations));
  assert.ok(relations.includes('delegate_permission/common.handle_all_urls'));
  assert.ok(relations.includes('delegate_permission/common.get_login_creds'));
});
