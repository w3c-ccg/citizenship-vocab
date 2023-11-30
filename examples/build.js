/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */

// generate citizenship vocab spec examples

// debugging globals
const verbose = true;
const diagnoseCborLd = verbose || false;

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {cryptosuite as ecdsaRdfc2019Cryptosuite} from
  '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
//import * as vc from '@digitalbazaar/vc';
import * as vc from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {driver} from '@digitalbazaar/did-method-key';
import {fileURLToPath} from 'node:url';
import fs from 'node:fs/promises';
import path from 'node:path';
import {util} from '@digitalbazaar/vpqr';

const {toQrCode} = util;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// setup document loader
import {CachedResolver} from '@digitalbazaar/did-io';
import {securityLoader} from '@digitalbazaar/security-document-loader';

//import secCtx from '@digitalbazaar/security-context';
import diCtx from '@digitalbazaar/data-integrity-context';
import credV2Ctx from '@digitalbazaar/credentials-v2-context';

const loader = securityLoader();
const contexts = [
  diCtx,
  credV2Ctx
];
for(const context of contexts) {
  for(const [url, c] of context.contexts.entries()) {
    loader.addStatic(url, c);
  }
}
for(const v of ['1', '2']) {
  const json = await fs.readFile(
    path.join(__dirname, `../contexts/citizenship-v${v}.jsonld`));
  const context = JSON.parse(json);
  loader.addStatic(`https://w3id.org/citizenship/v${v}`, context);
}

const resolver = new CachedResolver();
const didKeyDriverMultikey = driver();

didKeyDriverMultikey.use({
  multibaseMultikeyHeader: 'zDna',
  fromMultibase: EcdsaMultikey.from
});
resolver.use(didKeyDriverMultikey);
loader.setDidResolver(resolver);

const documentLoader = loader.build();

// generate new key
// NOTE: this will be different every run
async function generateKey() {
  // generate example ecdsa keypair
  const ecdsaKeyPair = await EcdsaMultikey.generate({curve: 'P-256'});

  const {
    didDocument, keyPairs, methodFor
  } = await didKeyDriverMultikey.fromKeyPair({
    verificationKeyPair: ecdsaKeyPair
  });
  ecdsaKeyPair.id = didDocument.assertionMethod[0];
  ecdsaKeyPair.controller = didDocument.id;

  return ecdsaKeyPair;
}

// example key
// NOTE: use this to limit test output changes
async function exampleKey() {
}

async function sign({
  credential,
  ecdsaKeyPair,
  date,
  documentLoader
}) {
  // setup ecdsa-rdfc-2019 signing suite
  const signingSuite = new DataIntegrityProof({
    signer: ecdsaKeyPair.signer(),
    date: '2023-01-01T01:01:01Z',
    cryptosuite: ecdsaRdfc2019Cryptosuite
  });

  // sign credential
  const verifiableCredential = await vc.issue({
    credential,
    suite: signingSuite,
    documentLoader
  });

  // setup ecdsa-rdfc-2019 verifying suite
  const verifyingSuite = new DataIntegrityProof({
    cryptosuite: ecdsaRdfc2019Cryptosuite
  });

  // verify signed credential (only done to check)
  const verifyResult = await vc.verifyCredential({
    credential: verifiableCredential,
    suite: verifyingSuite,
    documentLoader
  });

  return {
    verifiableCredential
  };
}

async function _example({name}) {
  console.log(`=== BUILDING: name=${name}`);

  // track data for use in templates
  const data = {};

  const inputJson = await fs.readFile(
    path.join(__dirname, `${name}.jsonld`), 'utf8');

  const input = JSON.parse(inputJson);

  // generate new key
  const ecdsaKeyPair = await generateKey();
  // use static key to avoid test output churn
  //const keyPair = await exampleKey();

  // set signing date
  // NOTE: using static date to limit test output changes
  const date = '2023-01-01T01:01:01Z';

  // set issuer to key controller
  input.issuer = ecdsaKeyPair.controller;

  if(verbose) {
    console.log(`=== INPUT WITH ISSUER: name=${name}`);
    console.log(input);
  }

  // sign
  const {verifiableCredential} = await sign({
    credential: input,
    ecdsaKeyPair,
    date,
    documentLoader
  });

  data.vc = verifiableCredential;
  data.vcJsonLd = JSON.stringify(verifiableCredential);

  if(verbose) {
    console.log(`=== VC: name=${name}`);
    console.log(data.vc);
  }

  // write out signed data
  await fs.writeFile(
    path.join(__dirname, `${name}-signed.jsonld`),
    JSON.stringify(data.vc, null, 2));

  // create QR code
  const {
    version, payload, imageDataUrl, encodedCborld, rawCborldBytes
  } = await toQrCode({
    header: 'VC1-',
    jsonldDocument: verifiableCredential,
    documentLoader,
    diagnose: diagnoseCborLd ? console.log : null
  });

  data.vcQrCodeVersion = version;
  data.vcRawCborLd = rawCborldBytes;
  data.vcEncodedCborLd = encodedCborld;
  data.vcQrPayload = payload;
  data.vcQrCode = imageDataUrl;

  if(verbose) {
    console.log(`=== VC QR CODE VERSION: name=${name}`);
    console.log(data.vcQrCodeVersion);
    console.log(`=== VC RAW CBOR-LD: ` +
      `name=${name} length=${data.vcRawCborLd.length}`);
    console.log(data.vcRawCborLd);
    console.log(`=== VC ENCODED CBOR-LD: ` +
      `name=${name} length=${data.vcEncodedCborLd.length}`);
    console.log(data.vcEncodedCborLd);
    console.log(`=== VC QR PAYLOAD: ` +
      `name=${name} length=${data.vcQrPayload.length}`);
    console.log(data.vcQrPayload);
    console.log(`=== VC QR CODE: ` +
      `name=${name} length=${data.vcQrCode.length}`);
    console.log(data.vcQrCode);
  }

  // write out QR code HTML
  const qrcodeHTML = `
<dl>
  <dt>QR Code</dt>
  <dd><img alt="QR" src="${data.vcQrCode}"/></dd>
  <dt>QR Code Version</dt>
  <dd>${data.vcQrCodeVersion}</dd>
</dl>
  `;
  await fs.writeFile(
    path.join(__dirname, `${name}-qrcode.html`),
    qrcodeHTML);

  // write out info HTML
  const infoHTML = `
<div>
  <table class="simple">
    <thead>
      <tr>
        <th>Property</th>
        <th>Value</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>QR Code Version</td>
        <td>12</td>
      </tr>
      <tr>
        <td>Verifiable Credential JSON-LD</td>
        <td>${data.vcJsonLd.length} bytes</td>
      </tr>
      <tr>
        <td>Raw CBOR-LD</td>
        <td>${data.vcRawCborLd.length} bytes</td>
      </tr>
      <tr>
        <td>Encoded CBOR-LD</td>
        <td>${data.vcEncodedCborLd.length} bytes</td>
      </tr>
      <tr>
        <td>QR Payload</td>
        <td>${data.vcQrPayload.length} bytes</td>
      </tr>
      <tr>
        <td>QR Code Image URL</td>
        <td>${data.vcQrCode.length} bytes</td>
      </tr>
    </tbody>
  </table>
</div>
  `;
  await fs.writeFile(
    path.join(__dirname, `${name}-info.html`),
    infoHTML);

  console.log(`=== DONE: name=${name}`);
}

async function main() {
  const examples = [
    'citizenship',
    'ead',
    'naturalization',
    'prc'
  ];
  for(const example of examples) {
    await _example({name: example});
  }
}

await main();
