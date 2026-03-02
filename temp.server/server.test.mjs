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

test('registration keeps credential id stable for allowCredentials', async () => {
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
