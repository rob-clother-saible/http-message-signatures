import {
  createPrivateKey, createHash, sign
} from 'node:crypto';
import fetch from 'node-fetch';
import { readFileSync, existsSync } from 'node:fs';
import { v4 } from 'uuid';
import { loadEnvFile } from 'node:process';

loadEnvFile();

const griffinApiDomain = 'api.griffin.com';

function addSignatureHeaders({
  key,
  method = 'POST',
  query = '?',
  authority,
  path,
  headers,
  body,
}) {
  const privateKey = createPrivateKey(key.private);
  const nonce = v4();
  const hash = createHash('sha512');
  const digest = hash.update(body).digest('base64');
  const created = Math.floor(new Date().getTime()/1000);
  const components = [
    '@method',
    '@authority',
    '@path',
    'content-type',
    'content-length',
    'date',
    'content-digest',
    '@query'
  ].map(c => `"${c}"`).join(' ');
  const signatureParams = `(${components});created=${created};keyid="${key.id}";nonce="${nonce}"`;
  const contentDigestHeader = `sha-512=:${digest}:`;
  const signatureBase = `"@method": ${method}
"@authority": ${authority}
"@path": ${path}
"content-type": ${headers['Content-Type']}
"content-length": ${headers['Content-Length']}
"date": ${headers.Date}
"content-digest": ${contentDigestHeader}
"@query": ${query}
"@signature-params": ${signatureParams}`;
  console.log('Request body', body);
  console.log('Signature base', signatureBase);
  const signature = Buffer.from(
    // To sign the signature base using ED25519, set the first argument to null.
    // Setting it to "ed25519" breaks the implementation.
    sign(null, Buffer.from(signatureBase), { key: privateKey })
  ).toString('base64');
  return {
    ...headers,
    'Signature-Input': `sig1=${signatureParams}`,
    Signature: `sig1=:${signature}:`,
    'Content-Digest': contentDigestHeader,
  };
}

if (process.argv.length < 4) {
  console.log(`Usage: ${process.argv[1]} <method> <url_or_filename>`);
  console.log('method               HTTP Method(GET, POST, PUT, DELETE, PATCH)')
  console.log('url_or_filename      Griffin API endpoint and payload -- can be given as a plain URL or a JSON file name')
  process.exit(1)
}

const method = process.argv[2];
const uriOrFilename = process.argv[3];

if (!['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
  console.log(`method ${method} not supported`);
  process.exit(1);
}

function readUrlAndBody() {
  const startsWithApiRoot = uriOrFilename.startsWith(griffinApiDomain);
  if (uriOrFilename.startsWith('/') || startsWithApiRoot) {
    if (method !== 'GET' && method != 'DELETE') {
      console.log(`Invalid method: ${method}. You can only use GET if you use a plain URL.`);
      process.exit(1);
    }
    if (startsWithApiRoot) {
      return { uri: uriOrFilename, body: '' };
    }
    return uriOrFilename.startsWith('/v0/') ? { 
      uri: `https://${griffinApiDomain}${uriOrFilename}`,
      body: '' 
    } : {
      uri: `https://${griffinApiDomain}/v0${uriOrFilename}`,
      body: ''
    };
  }
  if (!existsSync(`commands/${uriOrFilename}`)) {
    console.log(`file ${uriOrFilename} not found`);
    process.exit(1);
  }
  const command = JSON.parse(readFileSync(`commands/${uriOrFilename}`, 'utf-8').trim());
  return command.endpoint.startsWith('/v0/') ? {
    uri: `https://${griffinApiDomain}${command.endpoint}`,
    body: JSON.stringify(command.body) 
  } : {
    uri: `https://${griffinApiDomain}/v0${command.endpoint}`,
    body: JSON.stringify(command.body) 
  };
}

const { uri, body } = readUrlAndBody();
if (!uri.startsWith(`https://${griffinApiDomain}/v0/`)) {
  console.log(`url ${uri} not supported`);
  process.exit(1);
}

const apiKey = process.env.GRIFFIN_API_KEY;
if (!apiKey) {
  console.log('Please set the GRIFFIN_API_KEY environment variable');
  process.exit(1);
}

const keyId = process.env.GRIFFIN_KEY_ID;
if (!keyId) {
  console.log('Please set the GRIFFIN_API_KEY environment variable');
  process.exit(1);
}

const privateKeyPath = process.env.GRIFFIN_PRIVATE_KEY_PATH || 'private_key.pem'
const privateKeyPem = readFileSync(privateKeyPath).toString();
const key = { id: keyId, private: privateKeyPem };
const headers = {
  Host: griffinApiDomain,
  Date: new Date().toUTCString(),
  'Content-Type': 'application/json',
  'Content-Length': Buffer.byteLength(body).toString(),
  Authorization: `GriffinAPIKey ${apiKey}`,
};
const { pathname, search } = new URL(uri);
const signedHeaders = await addSignatureHeaders({
  key,
  authority: griffinApiDomain,
  path: pathname,
  headers,
  body,
  query: search || '?',
  method,
});
console.log('Signed Headers', signedHeaders);
console.log('URL', uri);
const response = await fetch(uri, {
  method,
  headers: signedHeaders,
  body: body || undefined,
});
const contentType = response.headers.get('Content-Type');
if (!response.ok) {
  const text = await response.text();
  console.log('Response headers', response.headers);
  console.error('Failed API invocation', text);
} else if (contentType.startsWith('application/json')) {
  const json = await response.json();
  console.log('Response', json);
} else {
  console.log('Response', await response.text());
}
