const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const fs=require('fs');const path=require('path');const root=path.resolve(__dirname,'..');const fixture=name=>path.join(__dirname,'fixtures',name);
(async()=>{
const mf=new Miniflare(convertV4MiniflareOptions({workers:[{name:'hardening',modules:true,script:fs.readFileSync(path.join(root,'src/index.js'),'utf8'),compatibilityDate:'2026-11-01',d1Databases:['DB'],bindings:{FILE_SIG:'synthetic-test-key-never-used-in-production'},serviceBindings:{ASSETS:()=>new Response('test')}}]}));
try{
const db=await mf.getD1Database('DB');
let schema=fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8');
for(const sql of schema.split(';').filter(x=>x.trim())) await db.prepare(sql).run();
for(const sql of [
'ALTER TABLE users ADD COLUMN username TEXT','ALTER TABLE users ADD COLUMN email TEXT','ALTER TABLE users ADD COLUMN bio TEXT','ALTER TABLE users ADD COLUMN avatar_key TEXT','ALTER TABLE users ADD COLUMN history_granted INTEGER DEFAULT 0',
'ALTER TABLE tokens ADD COLUMN last_seen TEXT','ALTER TABLE tokens ADD COLUMN user_agent TEXT',
'ALTER TABLE messages ADD COLUMN deleted_at TEXT','ALTER TABLE messages ADD COLUMN deleted_by TEXT','ALTER TABLE messages ADD COLUMN edited_at TEXT',
'CREATE TABLE reads(user_id TEXT,channel TEXT,last_id INTEGER,PRIMARY KEY(user_id,channel))',
'CREATE TABLE receipts(message_id INTEGER,user_id TEXT,delivered_at TEXT,read_at TEXT,PRIMARY KEY(message_id,user_id))',
'CREATE TABLE typing(user_id TEXT,channel TEXT,name TEXT,ts TEXT,PRIMARY KEY(user_id,channel))',
'CREATE TABLE history_requests(id INTEGER PRIMARY KEY,user_id TEXT,status TEXT,created_at TEXT)',
])await db.prepare(sql).run();
for(const [id,role,created] of [['owner','owner','2026-01-01'],['member','member','2026-01-01'],['newmember','member','2099-01-01'],['pending','member','2026-01-01']]){
 await db.prepare('INSERT INTO users(id,name,username,pass_hash,role,approved,created_at) VALUES (?,?,?,?,?,?,?)').bind(id,id,id,'unused',role,id==='pending'?0:1,created).run();
 await db.prepare('INSERT INTO tokens(token,user_id,last_seen) VALUES (?,?,datetime(\'now\'))').bind(id+'token',id).run();
}

const results=[];
function check(name,ok,detail){results.push({name,pass:!!ok,detail});if(!ok)console.error('FAIL',name,detail);}
async function req(path,token='membertoken',body,method){return mf.dispatchFetch('http://test.local'+path,{method:method||(body?'POST':'GET'),headers:{...(token?{authorization:'Bearer '+token}:{}),'content-type':'application/json'},body:body?JSON.stringify(body):undefined});}
let r=await req('/api/me');check('active session',r.status===200,await r.text());
await db.prepare("UPDATE tokens SET last_seen=datetime('now','-121 minutes') WHERE token='membertoken'").run();
r=await req('/api/me');check('idle >2h denied',r.status===401,await r.text());
await db.prepare("INSERT INTO tokens VALUES ('membertoken','member',datetime('now'),datetime('now'),NULL)").run();
await db.prepare("UPDATE tokens SET last_seen=NULL WHERE token='membertoken'").run();
r=await req('/api/me');check('legacy session migration no forced relogin',r.status===200,await r.text());
await db.prepare("UPDATE tokens SET last_seen=datetime('now','-119 minutes') WHERE token='membertoken'").run();
r=await req('/api/me');check('119m still active',r.status===200,await r.text());
await db.prepare("UPDATE tokens SET last_seen=datetime('now','-60 minutes') WHERE token='membertoken'").run();
r=await mf.dispatchFetch('http://test.local/api/me',{headers:{authorization:'Bearer membertoken','x-session-passive':'1'}});const passive=await db.prepare("SELECT last_seen FROM tokens WHERE token='membertoken'").first();check('passive polling does not extend idle session',Date.now()-Date.parse(passive.last_seen.replace(' ','T')+'Z')>3500000,passive);
r=await req('/api/me');
const touch=await db.prepare("SELECT last_seen FROM tokens WHERE token='membertoken'").first();check('activity clock refreshed',Date.now()-Date.parse(touch.last_seen.replace(' ','T')+'Z')<5000,touch);
r=await req('/api/admin/pending');check('member admin denied',r.status!==200,r.status);
r=await req('/api/admin/role','ownertoken',{user_id:'member',role:'admin'});check('promote',r.status===200,await r.text());
r=await req('/api/admin/pending');check('promotion immediate',r.status===200,await r.text());
r=await req('/api/admin/role','ownertoken',{user_id:'member',role:'member'});check('demote',r.status===200,await r.text());
r=await req('/api/admin/pending');check('demotion immediate',r.status!==200,r.status);
const samples=[['png',fs.readFileSync(fixture('image.png')),'image/png',true],['jpeg',fs.readFileSync(fixture('image.jpg')),'image/jpeg',true],['pdf',Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF'),'application/pdf',true],['audio',fs.readFileSync(fixture('audio.webm')),'audio/webm',true],['html',Buffer.from('<html><script>alert(1)</script></html>'),'image/png',false],['svg',Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>'),'image/jpeg',false],['fake',Buffer.from('this is not an actual image file'),'image/png',false],['oversize',Buffer.alloc(15000001,65),'image/png',false]];
const keys={};
for(const [name,data,mime,allowed]of samples){
 r=await mf.dispatchFetch('http://test.local/api/file',{method:'POST',headers:{authorization:'Bearer membertoken','content-type':mime,'x-file-name':name},body:data});const d=await r.json();check('upload '+name,(r.status===200)===allowed,d);if(d.key)keys[name]=d.key;
}
r=await mf.dispatchFetch('http://test.local/api/audio',{method:'POST',headers:{authorization:'Bearer membertoken','content-type':'audio/webm'},body:fs.readFileSync(fixture('audio.webm'))});const ad=await r.json();check('audio recorder upload',r.status===200,ad);keys.voice=ad.key;
for(const [name,key]of Object.entries(keys)){
 await db.prepare('INSERT INTO messages(channel,user_id,name,body,file_key,audio_key) VALUES (?,?,?,?,?,?)').bind('general','member','member','fixture',name==='voice'?null:key,name==='voice'?key:null).run();
}
r=await req('/api/asset-links','membertoken',{items:Object.entries(keys).map(([n,k])=>({kind:n==='voice'?'audio':'file',key:k}))});const signed=await r.json();check('signed links issued',r.status===200,signed.error||Object.keys(signed.urls||{}).length);
for(const [name,key]of Object.entries(keys)){
 const kind=name==='voice'?'audio':'file',suffix=signed.urls[key];
 r=await req('/api/'+kind+'/'+key+suffix,null);check('open '+name,r.status===200,{status:r.status,type:r.headers.get('content-type')});
 check('nosniff '+name,r.headers.get('x-content-type-options')==='nosniff');
 if(name==='pdf')check('PDF protected attachment',r.headers.get('content-disposition').startsWith('attachment'));
 const tampered=suffix.replace('sig=','sig=0');r=await req('/api/'+kind+'/'+key+tampered,null);check('tampered '+name,r.status===401,r.status);
 const expired=new URLSearchParams(suffix);expired.set('exp','1');r=await req('/api/'+kind+'/'+key+'?'+expired,null);check('expired '+name,r.status===401,r.status);
 r=await req('/api/'+kind+'/'+key+'?t=membertoken',null);check('raw session URL rejected '+name,r.status===401,r.status);
}
r=await req('/api/messages?channel=general');let chat=await r.json();check('chat list and signed media',r.status===200&&chat.messages.length>0&&Object.keys(chat.urls).length>0,chat.error||chat.messages.length);
r=await req('/api/profile/member');let prof=await r.json();check('profile load',r.status===200,prof.error||prof.profile.id);
const key=keys.png;
r=await req('/api/file/not-the-signed-file'+signed.urls[key],null);check('cross-file signature denied',r.status===401,r.status);
r=await req('/api/audio/'+key+signed.urls[key],null);check('cross-kind signature denied',r.status===401,r.status);
r=await req('/api/asset-links','newmembertoken',{items:[{kind:'file',key}]});let d=await r.json();check('history-gated user cannot sign old file',!d.urls[key],d);
r=await req('/api/asset-links','pendingtoken',{items:[{kind:'file',key}]});check('pending user denied',[401,403].includes(r.status),r.status);
await db.prepare("UPDATE users SET approved=0 WHERE id='member'").run();r=await req('/api/file/'+key+signed.urls[key],null);check('access revoked invalidates signed link',r.status===401,r.status);
await db.prepare("UPDATE users SET approved=1 WHERE id='member'").run();
await db.prepare('UPDATE messages SET deleted_at=datetime(\'now\') WHERE file_key=?').bind(key).run();r=await req('/api/file/'+key+signed.urls[key],null);check('deleted file message denies old link',r.status===401,r.status);
r=await req('/api/logout','membertoken',{});r=await req('/api/me');check('logout immediately revoked',r.status===401,r.status);
for(const path of ['/api/me','/api/profile','/api/profile/password','/api/auth/sessions']) {
 r=await req(path,'pendingtoken',path==='/api/profile'?{bio:'not allowed'}:path==='/api/profile/password'?{current_password:'x',new_password:'123456'}:undefined);
 check('pending early route '+path,[401,403].includes(r.status),r.status);
}
r=await req('/dl/old-source.zip',null);check('legacy source archive blocked',r.status===403,r.status);
r=await req('/api/profile/owner?t=ownertoken',null);check('profile rejects URL session token',r.status===401,r.status);
r=await req('/api/asset-links','ownertoken',{items:[null]});check('malformed link request is 400',r.status===400,r.status);
await db.prepare("INSERT INTO tokens(token,user_id,last_seen) VALUES ('exact','member',datetime('now','-120 minutes'))").run();
r=await req('/api/me','exact');check('exact 2h idle denied',r.status===401,r.status);
for(const [name,data] of [['prefix-png',Buffer.from([137,80,78,71,...Buffer.alloc(40)])],['pdf-no-eof',Buffer.from('%PDF-1.4 random incomplete')],['generic-zip',Buffer.from([80,75,3,4,...Buffer.alloc(40)])]]) {
 r=await mf.dispatchFetch('http://test.local/api/file',{method:'POST',headers:{authorization:'Bearer ownertoken','content-type':'image/png'},body:data});check('reject '+name,r.status===400,r.status);
}
r=await req('/api/me','ownertoken');const me=await r.json();check('me retains account fields',Object.hasOwn(me.user,'avatar_key')&&Object.hasOwn(me.user,'email')&&me.user.username==='owner',me.user);

fs.mkdirSync(path.join(root,'review'),{recursive:true});
fs.writeFileSync(path.join(root,'review/security-results.json'),JSON.stringify(results,null,2));console.log(JSON.stringify({total:results.length,passed:results.filter(x=>x.pass).length,failed:results.filter(x=>!x.pass)}));
}finally{await mf.dispose();}
})().catch(e=>{console.error(e);process.exitCode=1;});
