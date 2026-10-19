import assert from 'node:assert/strict';
import { interop } from './interop-fixtures.mjs';
import { test } from 'node:test';
import { canonicalText } from '../dist/canonical.js';
import {
  TrustBundleError,
  lookupTrustBundle,
  parseDnsTxtResponse,
  readmeBlock,
  trustBundleBytes,
  trustBundleDigest,
  trustBundleFromReadme,
  trustBundleFromTxt,
  txtRecord,
  validateTrustBundle,
} from '../dist/trust.js';

const FIXTURE = interop('trust-bundle.json');
const bundle = FIXTURE.bundle;
const dns = FIXTURE.dns;
const response = Buffer.from(dns.response_hex, 'hex');

test('bundle: validateTrustBundle(jcs) deep-equals bundle', () => {
  assert.deepEqual(validateTrustBundle(FIXTURE.jcs), bundle);
});

test('jcs: trustBundleBytes(bundle) equals the jcs bytes', () => {
  assert.deepEqual(Buffer.from(trustBundleBytes(bundle)), Buffer.from(FIXTURE.jcs, 'utf8'));
});

test('sha256: trustBundleDigest(bundle) equals the fixture digest', () => {
  assert.equal(trustBundleDigest(bundle), FIXTURE.sha256);
});

test('txt_record: txtRecord(bundle) equals the fixture TXT record', () => {
  assert.equal(txtRecord(bundle), FIXTURE.txt_record);
});

test('readme_block: readmeBlock(bundle) equals the fixture README block', () => {
  assert.equal(readmeBlock(bundle), FIXTURE.readme_block);
});

test('readme_block: trustBundleFromReadme deep-equals bundle', () => {
  assert.deepEqual(trustBundleFromReadme(FIXTURE.readme_block), bundle);
});

test('readme_block_wrong_digest: trustBundleFromReadme throws TrustBundleError', () => {
  assert.throws(() => trustBundleFromReadme(FIXTURE.readme_block_wrong_digest.text), TrustBundleError);
});

test('txt_record: trustBundleFromTxt([txt_record]) deep-equals bundle', () => {
  assert.deepEqual(trustBundleFromTxt([FIXTURE.txt_record]), bundle);
});

test('dns.character_strings: trustBundleFromTxt deep-equals bundle', () => {
  assert.deepEqual(trustBundleFromTxt([dns.character_strings]), bundle);
});

test('dns.response_hex: parseDnsTxtResponse returns exactly [character_strings]', () => {
  assert.deepEqual(parseDnsTxtResponse(response, dns.qid, dns.qname), [dns.character_strings]);
});

test('dns.response_hex: parsed TXT records feed trustBundleFromTxt to bundle', () => {
  assert.deepEqual(trustBundleFromTxt(parseDnsTxtResponse(response, dns.qid, dns.qname)), bundle);
});

test('dns.response_hex: a different qid throws TrustBundleError', () => {
  assert.throws(() => parseDnsTxtResponse(response, dns.qid + 1, dns.qname), TrustBundleError);
});

test('dns.response_hex: a different qname throws TrustBundleError', () => {
  assert.throws(() => parseDnsTxtResponse(response, dns.qid, '_aics.other.test'), TrustBundleError);
});

test('dns.response_hex: a response truncated by one byte throws TrustBundleError', () => {
  assert.throws(() => parseDnsTxtResponse(response.subarray(0, response.length - 1), dns.qid, dns.qname), TrustBundleError);
});

test('dns.response_hex: a response with RCODE 3 throws TrustBundleError', () => {
  const nxdomain = Buffer.from(response);
  nxdomain.writeUInt16BE((response.readUInt16BE(2) & 0xfff0) | 3, 2);
  assert.throws(() => parseDnsTxtResponse(nxdomain, dns.qid, dns.qname), TrustBundleError);
});

for (const bad of FIXTURE.invalid) {
  test(`invalid: ${bad.name} throws TrustBundleError`, () => {
    if (bad.jcs !== undefined) {
      assert.throws(() => validateTrustBundle(bad.jcs), TrustBundleError);
    } else {
      assert.throws(() => validateTrustBundle(Buffer.from(bad.bytes_u64, 'base64url')), TrustBundleError);
      assert.throws(() => trustBundleFromTxt(['aics1=' + bad.bytes_u64]), TrustBundleError);
    }
  });
}

test('two TXT records with different valid bundles throw TrustBundleError', () => {
  const other = { ...bundle, bootstrap_card_hash: 'ff'.repeat(32) };
  assert.throws(() => trustBundleFromTxt([FIXTURE.txt_record, txtRecord(other)]), TrustBundleError);
});

test('two identical TXT records are accepted', () => {
  assert.deepEqual(trustBundleFromTxt([FIXTURE.txt_record, FIXTURE.txt_record]), bundle);
  assert.deepEqual(trustBundleFromTxt([dns.character_strings, dns.character_strings]), bundle);
});

test('no aics1= record throws TrustBundleError', () => {
  assert.throws(() => trustBundleFromTxt(['v=spf1 -all', 'some-other=1']), TrustBundleError);
});

test('lookupTrustBundle resolves bundle via an injected resolver for _aics.<domain>', async () => {
  const resolved = await lookupTrustBundle('interop.test', async (name) => {
    assert.equal(name, '_aics.interop.test');
    return [dns.character_strings];
  });
  assert.deepEqual(resolved, bundle);
});

test('a bundle whose log, policy and owner keys are not distinct throws', () => {
  const bad = { ...bundle, owner_kid: bundle.policy_kid };
  assert.throws(() => validateTrustBundle(canonicalText(bad)), TrustBundleError);
});
