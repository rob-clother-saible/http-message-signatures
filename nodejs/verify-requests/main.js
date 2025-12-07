import {
  createPublicKey, createPrivateKey, createHash, sign
} from 'node:crypto';
import fetch from 'node-fetch';
import { v4 } from 'uuid';

const griffinApiDomain = 'api.griffin.com';

export function verifySignature({
  key,
  method = 'POST',
  authority,
  path,
  body,
  date,
  contentType,
  contentLength,
  contentDigest,
  signatureParams,
  signature,
}) {
  const hash = createHash('sha512');
  const digest = hash.update(body).digest('base64');
  const contentDigestHeader = `sha-512=:${digest}:`;
  if (contentDigest !== contentDigestHeader) {
    console.log('Content Digest mismatch');
    return false;
  }

  const components = signatureParams
    .split(';')[0]
    .replace(/[()]/g, '')
    .split(' ')
    .map((c) => c.replace(/"/g, ''));
  const readComponent = {
    date: () => date,
    '@method': () => method,
    '@path': () => path,
    '@authority': () => authority,
    'content-type': () => contentType,
    'content-length': () => contentLength,
    'content-digest': () => contentDigest,
  };
  const signatureBase = `${components.map((c) => `"${c}": ${readComponent[c]()}`).join('\n')}
"@signature-params": ${signatureParams}`;
  const publicKeyObject = JSON.parse(key.public);
  const publicKey = createPublicKey({ key: publicKeyObject, format: 'jwk' });
  return verify('sha512', Buffer.from(signatureBase), publicKey, Buffer.from(signature, 'base64'));
}

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

function getSignedHeaders(body, path, method) {
  const apiKey = process.env.GRIFFIN_API_KEY;
  if (!apiKey) {
    console.log('Please set the GRIFFIN_API_KEY environment variable');
    process.exit(1);
  }

  const keyId = process.env.GRIFFIN_KEY_ID;
  if (!keyId) {
    console.log('Please set the GRIFFIN_KEY_ID environment variable');
    process.exit(1);
  }

  const privateKeyPath = process.env.GRIFFIN_PRIVATE_KEY_PATH || 'private_key.pem'
  const privateKeyPem = readFileSync(privateKeyPath).toString();
  const key = {
    id: keyId,
    private: privateKeyPem,
  };
  const headers = {
    Host: griffinApiDomain,
    Date: new Date().toUTCString(),
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body).toString(),
    Authorization: `GriffinAPIKey ${apiKey}`,
  };
  const signedHeaders = addSignatureHeaders({
    key,
    authority: griffinApiDomain,
    path,
    query: '?',
    headers,
    body,
    method,
  });
  return { signedHeaders };
}

async function getPublicKey(kid) {
  // For best practice, cache the public key so that you don't have to invoke the Griffin API to 
  // const cachedPublicKey = await getCachedPublicKey(kid);
  // if (cachedPublicKey) {
  //   return cachedPublicKey;
  // }

  const body = '';
  const url = `https://${griffinApiDomain}/v0/security/public-keys`;
  const { signedHeaders } = getSignedHeaders(body, url, 'GET');
  const response = await fetch(url, {
    method: 'GET',
    headers: signedHeaders,
  });
  if (!response.ok) {
    const text = await response.text();
    console.log('Public keys not found', text);
    return null;
  }

  const result = await response.json();
  const key = result[kid];
  // For best practice, save the retrieved key to your cache
  // await writePublicKeyToCache(kid, key);
  return result[kid];
}

async function verifyIncomingMessage({
  method = 'POST',
  authority,
  path,
  headers,
  body,
}) {
  const signatureInput = headers['signature-input'];
  const signatureHeader = headers['signature'];
  const contentDigestHeader = headers['content-digest'];
  const contentLengthHeader = headers['content-length'];
  const contentTypeHeader = headers['content-type'];
  const dateHeader = headers['date'];
  if (!signatureInput) {
    console.log('Griffin webhook invoked without a signature-input.');
    return false;
  }

  if (!signatureHeader) {
    console.log('Griffin webhook invoked without a signature.');
    return false;
  }

  if (!contentDigestHeader) {
    console.log('Griffin webhook invoked without a content-digest.');
    return false;
  }

  if (!contentTypeHeader) {
    console.log('Griffin webhook invoked without a content-type.');
    return false;
  }

  if (!dateHeader) {
    console.log('Griffin webhook invoked without a date.');
    return false;
  }

  const [kid, ...signatureParamsValues] = signatureInput.split('=');
  if (!kid) {
    console.log('No key ID found in signature input.');
    return false;
  }

  const signatureParams = signatureParamsValues.join('=');
  if (!signatureParams) {
    console.log('No signature parameters found in signature input.');
    return false;
  }

  const params = signatureParams.split(';');
  if (params.length < 3) {
    console.log('Griffin webhook invoked with too few signature parameters.');
    return false;
  }

  const keyIdComponent = params.find((c) => c.startsWith('keyid='));
  if (!keyIdComponent) {
    console.log('No keyId found in signature input.');
    return false;
  }

  if (kid !== keyIdComponent.split('=')[1].replace(/"/g, '')) {
    console.log('The key ID in the signature input is inconsistent.');
  }

  const publicKey = await getPublicKey(kid);
  if (!publicKey) {
    console.log('A Griffin webhook has been called without a valid key ID.');
    return false;
  }

  const [signatureName, delimitedSignatureValue] = signatureHeader.split('=');
  if (signatureName !== kid) {
    console.log('The signature name does not match the key ID.');
    return false;
  }

  if (!delimitedSignatureValue) {
    console.log('No signature value found.');
    return false;
  }

  const signature = delimitedSignatureValue.replace(/:/g, '');
  return verifySignature({
    key: { public: publicKey },
    method,
    authority,
    path,
    body,
    date: dateHeader,
    contentType: contentTypeHeader,
    contentLength: contentLengthHeader,
    contentDigest: contentDigestHeader,
    signatureParams,
    signature: signature,
  });
}


export async function griffinWebhook(req, res) {
  if (
    !(await verifyIncomingMessage({
      method: req.method,
      authority: req.host,
      body: JSON.stringify(req.body),
      path: '/path/to/griffinWebhook', // Replace this with the path to the Griffin webhook in your system
      headers: req.headers,
    }))
  ) {
    // If the verification fails for any reason, don't be helpful. Log the failure
    // as a potential security error, and return a 404.
    console.log('Griffin event verification failure', req.body);
    res.sendStatus(404);
    return;
  }

  // From Griffin's Best Practices documentation
  // (https://docs.griffin.com/docs/guides/validate-event-notifications#best-practices),
  // the handler should return a 2xx status quickly and process the event asynchronously.
  console.log('Save the event to internal storage, and use a trigger to handle the event.');
  res.sendStatus(200);
}
