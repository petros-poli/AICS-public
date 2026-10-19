import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { hex, fromHex as bytes, fromB64 as b64 } from './interop-fixtures.mjs';
const fixture = name => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8'));
import * as tlog from '../dist/tlog.js';
import { sign } from '../dist/keys.js';
const v=fixture('tlog-python'), policy={quorum:1,witnesses:[v.witness_vkey],maxAgeSeconds:300};
const check=n=>tlog.verifyCheckpoint(v.notes[n],v.log_vkey,{policy,now:v.timestamp});
const reader={read:async path=>v.tiles[path]?b64(v.tiles[path]):null};
for(const [size,note] of Object.entries(v.notes))test(`Python signed checkpoint size ${size}`,()=>{
  const r=check(size);assert(r.ok,r.error);assert.equal(hex(r.checkpoint.root),v.roots[size]);assert.equal(r.freshness,'verified');assert.equal(r.witnesses.length,1);assert.equal(tlog.serializeNote(tlog.parseNote(note)),note);
});
for(const [i,p] of v.inclusion.entries())test(`RFC 9162 Python inclusion proof ${i}: ${p.index}/${p.size}`,()=>{
  const root=bytes(v.roots[p.size]),proof=p.hashes.map(b64),hash=tlog.leafHash(b64(v.leaves[p.index]));
  assert(tlog.verifyInclusion(hash,p.index,p.size,proof,root));assert(!tlog.verifyInclusion(hash,p.index,p.size,[...proof,new Uint8Array(32)],root));
  if(proof.length)assert(!tlog.verifyInclusion(hash,p.index,p.size,proof.slice(1),root));
});
for(const [i,p] of v.consistency.entries())test(`RFC 9162 Python consistency proof ${i}: ${p.old}->${p.new}`,()=>{
  const old=bytes(v.roots[p.old]),next=bytes(v.roots[p.new]),proof=p.hashes.map(b64);assert(tlog.verifyConsistency(p.old,p.new,old,next,proof));assert(!tlog.verifyConsistency(p.old,p.new,old,next,[...proof,new Uint8Array(32)]));
});
test('Empty roots, malformed hash lengths and large coordinates fail closed',()=>{
  assert(tlog.verifyConsistency(0,0,tlog.EMPTY_HASH,tlog.EMPTY_HASH,[]));assert(!tlog.verifyConsistency(0,1,new Uint8Array(32),bytes(v.roots[1]),[]));
  assert(!tlog.verifyInclusion(new Uint8Array(31),0,1,[],new Uint8Array(31)));assert(!tlog.verifyConsistency(1,2,new Uint8Array(31),new Uint8Array(32),[]));
  assert(!tlog.verifyInclusion(new Uint8Array(32),2**53,2**53,[],new Uint8Array(32)));
});
test('No 32-bit truncation in proof verifier',()=>{
  let root=tlog.leafHash(new Uint8Array()),proof=[];for(let i=0;i<33;i++){proof.push(root);root=tlog.nodeHash(root,root);} assert(tlog.verifyInclusion(tlog.leafHash(new Uint8Array()),2**33-1,2**33,proof,root));
});
test('Freshness and future bounds, quorum zero remains unproven',()=>{
  const stale=tlog.verifyCheckpoint(v.notes[513],v.log_vkey,{policy,now:v.timestamp+301});assert(!stale.ok);assert.equal(stale.status,'stale');
  const future=tlog.verifyCheckpoint(v.notes[513],v.log_vkey,{policy,now:v.timestamp-31});assert(!future.ok);assert.equal(future.future.length,1);
  const logOnly=tlog.parseNote(v.notes[513]);logOnly.signatures=logOnly.signatures.slice(0,1);const r=tlog.verifyCheckpoint(logOnly,v.log_vkey,{now:v.timestamp});assert(r.ok);assert.equal(r.freshness,'unproven');
});
test('Invalid recognized signature rejects checkpoint even with quorum zero',()=>{
  const n=tlog.parseNote(v.notes[513]);n.signatures[1].signature[10]^=1;assert(!tlog.verifyCheckpoint(n,v.log_vkey,{policy:{...policy,quorum:0},now:v.timestamp}).ok);
});
test('Duplicate recognized signatures rejected, duplicate unknown ignored',()=>{
  const n=tlog.parseNote(v.notes[513]);n.signatures.push(n.signatures[0]);assert(!tlog.verifyCheckpoint(n,v.log_vkey,{policy,now:v.timestamp}).ok);
  const u=tlog.parseNote(v.notes[513]),unknown={name:'unknown',keyId:new Uint8Array(4),signature:new Uint8Array(5)};u.signatures.push(unknown,unknown);assert(tlog.verifyCheckpoint(u,v.log_vkey,{policy,now:v.timestamp}).ok);
});
test('Reject alias witness keys, incorrect origin, malformed notes and vkeys',()=>{
  assert(!tlog.verifyCheckpoint(v.notes[513],v.log_vkey,{policy:{...policy,witnesses:[v.witness_vkey,v.witness_vkey]},now:v.timestamp}).ok);
  assert(!tlog.verifyCheckpoint(v.notes[513],v.log_vkey,{expectedOrigin:'other'}).ok);
  for(const n of [v.notes[513].trimEnd(),v.notes[513].replace('\n513\n','\n0513\n'),v.notes[513].replace('\n\n','\nextra\n\n')])assert(!tlog.verifyCheckpoint(n,v.log_vkey,{now:v.timestamp}).ok);
  assert.throws(()=>tlog.parseVkey(v.log_vkey.replace(/[0-9a-f]{8}/,'00000000')));
  assert.throws(()=>tlog.parseNote(new Uint8Array([255])));
});
test('At least sixteen unknown signature lines accepted',()=>{
  const n=tlog.parseNote(v.notes[513]);for(let i=0;i<20;i++)n.signatures.push({name:'unknown'+i,keyId:new Uint8Array(4),signature:new Uint8Array(64)});assert(tlog.verifyCheckpoint(n,v.log_vkey,{policy,now:v.timestamp}).ok);
});
test('Tile path encoding and entry bundle truncation checks',()=>{
  assert.equal(tlog.tileIndexPath(1234067),'x001/x234/067');assert.equal(tlog.tilePath(0,0,1),'tile/0/000.p/1');assert.throws(()=>tlog.tilePath(0,0,256));assert.throws(()=>tlog.parseEntryBundle(new Uint8Array([0])));assert.throws(()=>tlog.parseEntryBundle(new Uint8Array([0,3,1])));
});
test('Root, historical inclusion and consistency from Python tiles',async()=>{
  const tree=new tlog.TileTree(reader,513);await tree.verifyRoot(check(513).checkpoint);
  for(const n of [0,1,3,255,256,257,511,512,513])assert.equal(hex(await tree.root(n)),v.roots[n]);
  for(const p of v.inclusion)assert.deepEqual((await tree.inclusionProof(p.index,p.size)).map(x=>Buffer.from(x).toString('base64')),p.hashes);
  for(const p of v.consistency)assert.deepEqual((await tree.consistencyProof(p.old,p.new)).map(x=>Buffer.from(x).toString('base64')),p.hashes);
  assert.equal(Buffer.from(await tree.readEntry(512,check(513).checkpoint)).toString('base64'),v.leaves[512]);await tree.verifyExtension(check(257).checkpoint,check(513).checkpoint);
});
test('Retired partial tiles fall back to full replacements',async()=>{
  const tree=new tlog.TileTree(reader,255);assert.equal(hex(await tree.root()),v.roots[255]);assert.equal(Buffer.from(await tree.readEntry(254,check(255).checkpoint)).toString('base64'),v.leaves[254]);
});
test('Corrupt tile, entry or proof cannot become trusted',async()=>{
  const corrupt={read:async path=>{const data=await reader.read(path);if(data&&path==='tile/0/002.p/1')data[0]^=1;return data;}};
  await assert.rejects(()=>new tlog.TileTree(corrupt,513).verifyRoot(check(513).checkpoint));
  const corruptEntry={read:async path=>{const data=await reader.read(path);if(data&&path.startsWith('tile/entries/'))data[4]^=1;return data;}};
  await assert.rejects(()=>new tlog.TileTree(corruptEntry,513).readEntry(512,check(513).checkpoint));
  await assert.rejects(()=>new tlog.TileTree({read:async()=>null},513).root(),tlog.TileMissingError);
});
test('HTTP mirror fallback and no redirect acceptance',async t=>{
  const requests=[];const server=createServer((req,res)=>{requests.push(req.url);if(req.url.startsWith('/missing/')){res.statusCode=404;res.end();}else if(req.url.startsWith('/redirect/')){res.statusCode=302;res.setHeader('location','/good/checkpoint');res.end();}else{const path=req.url.slice('/good/'.length);if(path==='checkpoint')res.end(v.notes[513]);else if(v.tiles[path])res.end(Buffer.from(v.tiles[path],'base64'));else{res.statusCode=404;res.end();}}});
  server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(resolve=>server.close(resolve)));const base=`http://127.0.0.1:${server.address().port}`;
  const r=new tlog.HttpTileReader([base+'/missing',base+'/good'],{allowHttp:true});await new tlog.TileTree(r,513).verifyRoot(check(513).checkpoint);assert(requests.some(p=>p.startsWith('/missing/'))&&requests.some(p=>p.startsWith('/good/')));
  await assert.rejects(()=>new tlog.HttpTileReader([base+'/redirect'],{allowHttp:true}).read('checkpoint'));
  assert.throws(()=>new tlog.HttpTileReader([base]));
});
test('Fresh witness verification requires a finite clock and age policy',()=>{
  assert(!tlog.verifyCheckpoint(v.notes[513],v.log_vkey,{policy,now:NaN}).ok);
  assert(!tlog.verifyCheckpoint(v.notes[513],v.log_vkey,{policy,now:v.timestamp,maxFutureSeconds:NaN}).ok);
  const noAge={quorum:1,witnesses:[v.witness_vkey]};assert(!tlog.verifyCheckpoint(v.notes[513],v.log_vkey,{policy:noAge,now:v.timestamp}).ok);
  const historical=tlog.verifyCheckpoint(v.notes[513],v.log_vkey,{policy:noAge,archived:true});assert(historical.ok);assert.equal(historical.freshness,'unproven');
});
