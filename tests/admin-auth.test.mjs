import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync, unlinkSync} from 'node:fs';
import {fileURLToPath, pathToFileURL} from 'node:url';

const apiFile=fileURLToPath(new URL('../netlify/functions/api.mjs',import.meta.url));
const mockFile=fileURLToPath(new URL('./.api-mock-temporary.mjs',import.meta.url));
const original=readFileSync(apiFile,'utf8');
const prefix=`
const data=globalThis.__aiedapMockData;
const getStore=()=>({
  async get(k,{type}={}){return data.has(k)?structuredClone(data.get(k)):null},
  async setJSON(k,v,opt={}){if(opt.onlyIfNew&&data.has(k))return {modified:false};data.set(k,structuredClone(v));return {modified:true}},
  async set(k,v){data.set(k,structuredClone(v));return {modified:true}},
  async list({prefix=''}){return {blobs:[...data.keys()].filter(k=>k.startsWith(prefix)).map(key=>({key}))}},
  async delete(k){data.delete(k)}
});
`;
globalThis.__aiedapMockData=new Map();
delete process.env.AIEDAP_SESSION_SECRET;
delete process.env.AIEDAP_ADMIN_CODE;
process.env.CONTEXT='production';
writeFileSync(mockFile,original.replace("import { getStore } from '@netlify/blobs';",prefix));
let backend;
try{backend=(await import(pathToFileURL(mockFile).href)).default}
finally{unlinkSync(mockFile)}

async function request(op,body,token){
  const hasBody=body!==undefined;
  const req=new Request('https://unit-test.invalid/api?op='+op,{
    method:hasBody?'POST':'GET',
    headers:hasBody?{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})}:(token?{Authorization:'Bearer '+token}:{}),
    ...(hasBody?{body:JSON.stringify(body)}:{})
  });
  const res=await backend(req);
  return {status:res.status,data:await res.json()};
}

test('Admin bootstrap requires rotation, stores salted hash, invalidates sessions',async()=>{
  let r=await request('config');
  assert.equal(r.status,200);
  assert.equal(globalThis.__aiedapMockData.get('auth/session-key')?.key?.length>30,true);

  r=await request('login',{role:'admin',adminCode:'incorrect'});
  assert.equal(r.status,403);

  r=await request('login',{role:'admin',adminCode:'9876'});
  assert.equal(r.status,200);
  assert.equal(r.data.mustChangePassword,true);
  const firstToken=r.data.token;

  r=await request('admin-users',undefined,firstToken);
  assert.equal(r.status,403,'Cannot administer groups before resetting initial password');

  r=await request('admin-password',{currentPassword:'bad',newPassword:'LongEnoughPass2026!'},firstToken);
  assert.equal(r.status,403);
  r=await request('admin-password',{currentPassword:'9876',newPassword:'short'},firstToken);
  assert.equal(r.status,400);

  r=await request('admin-password',{currentPassword:'9876',newPassword:'LongEnoughPass2026!'},firstToken);
  assert.equal(r.status,200);
  const tokenAfterRotation=r.data.token;
  const stored=globalThis.__aiedapMockData.get('auth/admin-password');
  assert.ok(stored?.salt);
  assert.ok(stored?.passwordHash);
  assert.equal(JSON.stringify(stored).includes('LongEnoughPass2026!'),false);

  r=await request('admin-users',undefined,firstToken);
  assert.equal(r.status,401,'Initial token must be invalid after rotation');

  r=await request('login',{role:'admin',adminCode:'9876'});
  assert.equal(r.status,403,'Initial 9876 password must stop working');
  r=await request('login',{role:'admin',adminCode:'LongEnoughPass2026!'});
  assert.equal(r.status,200);
  assert.equal(r.data.mustChangePassword,false);

  r=await request('admin-users',undefined,tokenAfterRotation);
  assert.equal(r.status,200);

  const previousToken=r.data.token;
  r=await request('admin-password',{currentPassword:'LongEnoughPass2026!',newPassword:'EvenBetterPass2026!'},tokenAfterRotation);
  assert.equal(r.status,200);
  r=await request('admin-users',undefined,tokenAfterRotation);
  assert.equal(r.status,401);
  r=await request('login',{role:'admin',adminCode:'EvenBetterPass2026!'});
  assert.equal(r.status,200);
});
