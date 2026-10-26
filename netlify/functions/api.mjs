import { getStore } from '@netlify/blobs';
import { createHmac, createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';

const LIMIT_PDF = 12 * 1024 * 1024;
const PART_SIZE = 720 * 1024;
const MAX_PARTS = Math.ceil(LIMIT_PDF/PART_SIZE);
const js = (x,status=200)=>new Response(JSON.stringify(x),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const err=(msg,status=400)=>js({error:msg},status);
const hash=s=>createHash('sha256').update(s).digest('hex');
const norm=s=>String(s??'').trim().replace(/\s+/g,' ').slice(0,80);
const secureEq=(a,b)=>{const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length && timingSafeEqual(x,y)};
const secret=()=>process.env.AIEDAP_SESSION_SECRET;
const sign=p=>{const d=Buffer.from(JSON.stringify({...p,exp:Date.now()+14*86400e3})).toString('base64url');const h=createHmac('sha256',secret()).update(d).digest('base64url');return d+'.'+h};
function session(req){const token=req.headers.get('authorization')?.replace(/^Bearer\s+/i,'');if(!token)return null;try{const [d,s]=token.split('.');if(!d||!s)return null;const h=createHmac('sha256',secret()).update(d).digest('base64url');if(!secureEq(h,s))return null;const p=JSON.parse(Buffer.from(d,'base64url'));return p.exp>Date.now()?p:null;}catch{return null;}}
const store=()=>getStore({name:'aiedap-m1-'+(process.env.CONTEXT==='production'?'production':('sandbox-'+(process.env.DEPLOY_ID||'local').slice(0,12))),consistency:'strong'});
const load=async(s,key)=>await s.get(key,{type:'json'});
const put=(s,key,obj,options)=>s.setJSON(key,obj,options);
const list=async(s,prefix)=> (await s.list({prefix})).blobs.map(x=>x.key);
const safeText=(x,n=3000)=>String(x??'').trim().slice(0,n);
function defaults(){return {mode:'groups',groups:Array.from({length:10},(_,i)=>({id:'g'+(i+1),label:(i+1)+'모둠',capacity:6})),updatedAt:new Date().toISOString()}}
async function settings(s){return (await load(s,'settings'))||defaults()}
async function profile(s,user){if(user?.role==='admin')return user;const p=await load(s,'people/'+user?.id);return p?{...p,role:'member'}:null;}
const authorized=(user,p)=>user?.role==='admin'||(p?.id===user?.id)||false;
async function visible(s,user,post){if(!post)return false;const st=await settings(s);if(user.role==='admin'||st.mode==='all')return true;const p=await profile(s,user);return p?.group===post.group;}
async function records(s,prefix){const keys=await list(s,prefix);return (await Promise.all(keys.map(k=>load(s,k)))).filter(Boolean)}
async function uploadDelete(s,id,parts){for(let n=0;n<parts;n++)await s.delete('pdfparts/'+id+'/'+n);}
async function readPDFParts(s,meta){const parts=[];for(let n=0;n<meta.parts;n++){const chunk=await s.get('pdfparts/'+meta.fileId+'/'+n,{type:'arrayBuffer'});if(!chunk)throw Error('PDF 파일 조각이 없습니다.');parts.push(new Uint8Array(chunk));}return parts;}
function merge(parts){const out=new Uint8Array(parts.reduce((v,a)=>v+a.length,0));let offset=0;for(const v of parts){out.set(v,offset);offset+=v.length;}return out;}
const respondPDF=bytes=>new Response(bytes,{headers:{'content-type':'application/pdf','content-disposition':'inline; filename="lesson.pdf"','cache-control':'private, max-age=120','x-content-type-options':'nosniff'}});
async function bodyJSON(req){try{return await req.json()}catch{return {}}}

export default async function handler(req){
 if(!secret()||!process.env.AIEDAP_ADMIN_CODE||!process.env.AIEDAP_JOIN_CODE)return err('서버 초기설정이 필요합니다. Netlify 환경변수 3개를 확인해 주세요.',503);
 const s=store(),url=new URL(req.url),op=url.searchParams.get('op')||'config';
 if(op==='config'&&req.method==='GET'){
   const st=await settings(s);const people=await records(s,'people/');return js({mode:st.mode,groups:st.groups.map(g=>({...g,count:people.filter(p=>p.group===g.id).length})),total:people.length,ready:true});
 }
 if(op==='login'&&req.method==='POST'){
   const b=await bodyJSON(req);
   if(b.adminCode){if(!secureEq(b.adminCode,process.env.AIEDAP_ADMIN_CODE))return err('운영자 코드가 틀립니다.',403);return js({token:sign({role:'admin',id:'admin'}),role:'admin',name:'운영자'});}
   if(!secureEq(b.joinCode,process.env.AIEDAP_JOIN_CODE))return err('연수 참여 코드가 맞지 않습니다.',403);
   const name=norm(b.name),school=norm(b.school),pin=safeText(b.pin,32);
   if(name.length<2||school.length<2||!/^\d{6,12}$/.test(pin))return err('성명·학교(각 2자 이상)와 개인 PIN(숫자 6~12자리)을 입력해 주세요.');
   const id=hash(school.toLowerCase()+'|'+name.toLowerCase()).slice(0,32),key='people/'+id;
   let person=await load(s,key);
   if(person){const test=scryptSync(pin,person.salt,64).toString('hex');if(!secureEq(test,person.pinhash))return err('동일한 성명·학교의 PIN이 일치하지 않습니다.',403);}
   else{
     const st=await settings(s),group=st.groups.find(g=>g.id===b.group);if(!group)return err('모둠을 선택해 주세요.');
     const people=await records(s,'people/');if(people.length>=60)return err('참가 인원이 60명에 도달했습니다. 운영자에게 문의하세요.',409);
     if(people.filter(p=>p.group===group.id).length>=group.capacity)return err('선택한 모둠이 가득 찼습니다. 다른 모둠을 선택해 주세요.',409);
     const salt=randomBytes(16).toString('hex');person={id,name,school,group:group.id,pinhash:scryptSync(pin,salt,64).toString('hex'),salt,joinedAt:new Date().toISOString()};
     const outcome=await put(s,key,person,{onlyIfNew:true});if(!outcome.modified)return err('동일 계정의 동시 등록이 확인되었습니다. 다시 로그인해 주세요.',409);
   }
   return js({token:sign({role:'member',id}),role:'member',user:{id,name:person.name,school:person.school,group:person.group}});
 }
 const token=session(req);if(!token)return err('로그인이 필요하거나 로그인 유효기간이 지났습니다.',401);
 const who=await profile(s,token);if(!who)return err('참가자 정보를 찾을 수 없습니다.',401);
 if(op==='me'&&req.method==='GET')return js({user:{id:who.id,name:who.name||'운영자',school:who.school||'',group:who.group||null},role:who.role});
 if(op==='dashboard'&&req.method==='GET'){
    const st=await settings(s);const posts=(await records(s,'posts/')).filter(p=>who.role==='admin'||st.mode==='all'||p.group===who.group).sort((a,b)=>b.updatedAt.localeCompare(a.updatedAt));
    const comments=(await records(s,'comments/')).filter(c=>posts.some(p=>p.id===c.postId));
    return js({mode:st.mode,posts:posts.map(p=>({...p,commentCount:comments.filter(c=>c.postId===p.id).length})),comments,me:{id:who.id,name:who.name||'운영자',group:who.group||null},groups:st.groups});
 }
 if(op==='upstart'&&req.method==='POST'){
    if(who.role!=='member')return err('연수생만 제출할 수 있습니다.',403);
    const b=await bodyJSON(req),size=Number(b.size),parts=Math.ceil(size/PART_SIZE),filename=safeText(b.filename,100);
    if(!filename.toLowerCase().endsWith('.pdf')||!Number.isSafeInteger(size)||size<100||size>LIMIT_PDF||parts<1||parts>MAX_PARTS)return err('PDF 파일(최대 12MB)만 업로드 가능합니다.');
    const id=randomUUID(),meta={fileId:id,owner:who.id,filename,size,parts,status:'uploading',createdAt:Date.now()};await put(s,'uploads/'+id,meta);return js({uploadId:id,partSize:PART_SIZE,parts});
 }
 if(op==='uppart'&&req.method==='POST'){
    const id=url.searchParams.get('id'),n=Number(url.searchParams.get('n'));
    const meta=await load(s,'uploads/'+id);if(!meta||meta.owner!==who.id||meta.status!=='uploading'||!Number.isInteger(n)||n<0||n>=meta.parts)return err('업로드 정보가 올바르지 않습니다.',403);
    const buffer=await req.arrayBuffer();if(buffer.byteLength<1||buffer.byteLength>PART_SIZE)return err('PDF 분할 크기가 올바르지 않습니다.');
    await s.set('pdfparts/'+id+'/'+n,buffer);return js({ok:true,part:n});
 }
 if(op==='upfinish'&&req.method==='POST'){
    const b=await bodyJSON(req),meta=await load(s,'uploads/'+b.uploadId);
    if(!meta||meta.owner!==who.id||meta.status!=='uploading')return err('업로드 권한 또는 상태가 올바르지 않습니다.',403);
    let bytes;try{bytes=merge(await readPDFParts(s,meta));if(bytes.length!==meta.size)throw Error('전송한 크기와 PDF 크기가 다릅니다.');if(new TextDecoder().decode(bytes.subarray(0,5))!=='%PDF-')throw Error('PDF 파일이 아닙니다.');const pdf=await PDFDocument.load(bytes,{ignoreEncryption:false});if(pdf.getPageCount()!==3)throw Error('수업 사례는 정확히 3쪽 PDF여야 합니다. 현재 '+pdf.getPageCount()+'쪽입니다.');}catch(e){return err(safeText(e.message,200));}
    meta.status='ready';await put(s,'uploads/'+b.uploadId,meta);return js({ok:true,uploadId:b.uploadId,filename:meta.filename,pages:3});
 }
 if(op==='publish'&&req.method==='POST'){
    if(who.role!=='member')return err('연수생만 제출할 수 있습니다.',403);
    const b=await bodyJSON(req),meta=await load(s,'uploads/'+b.uploadId);
    if(!meta||meta.owner!==who.id||meta.status!=='ready')return err('검증된 3쪽 PDF를 먼저 올려 주세요.');
    const title=safeText(b.title,120),course=safeText(b.course,120),summary=safeText(b.summary,1500),question=safeText(b.question,800);
    if(title.length<2||course.length<2||summary.length<10||question.length<5)return err('수업명, 교과, 핵심 활동·강점, 함께 고민할 질문을 작성해 주세요.');
    const old=await load(s,'posts/'+who.id),now=new Date().toISOString();
    const post={id:who.id,authorId:who.id,author:who.name,school:who.school,group:who.group,title,course,summary,question,uploadId:b.uploadId,filename:meta.filename,createdAt:old?.createdAt||now,updatedAt:now};await put(s,'posts/'+who.id,post);
    return js({ok:true,post});
 }
 if(op==='comment'&&req.method==='POST'){
    const b=await bodyJSON(req),post=await load(s,'posts/'+b.postId);
    if(!await visible(s,who,post))return err('해당 사례에 접근할 수 없습니다.',403);
    if(who.id===post.authorId)return err('자신의 사례에는 동료 피드백을 남길 수 없습니다.');
    if(!['learn','ask','apply'].includes(b.kind)||safeText(b.text,2000).length<5)return err('피드백 종류와 5자 이상의 내용을 작성해 주세요.');
    const row={id:randomUUID(),postId:post.id,group:post.group,authorId:who.id,author:who.name||'운영자',kind:b.kind,text:safeText(b.text,2000),createdAt:new Date().toISOString()};await put(s,'comments/'+row.id,row,{onlyIfNew:true});return js({ok:true,comment:row});
 }
 if(op==='comment-delete'&&req.method==='POST'){
    const b=await bodyJSON(req),c=await load(s,'comments/'+b.id);if(!c)return err('댓글이 없습니다.',404);if(who.role!=='admin'&&c.authorId!==who.id)return err('본인 댓글만 삭제할 수 있습니다.',403);await s.delete('comments/'+c.id);return js({ok:true});
 }
 if(op==='pdf'&&req.method==='GET'){
    const post=await load(s,'posts/'+url.searchParams.get('post'));if(!await visible(s,who,post))return err('권한이 없습니다.',403);
    const meta=await load(s,'uploads/'+post.uploadId);if(!meta||meta.status!=='ready')return err('PDF를 찾을 수 없습니다.',404);return respondPDF(merge(await readPDFParts(s,meta)));
 }
 if(op==='admin-settings'&&req.method==='POST'){
    if(who.role!=='admin')return err('운영자만 가능합니다.',403);const b=await bodyJSON(req),cnt=Number(b.count),cap=Number(b.capacity),mode=b.mode;
    if(!['groups','all'].includes(mode)||!Number.isInteger(cnt)||cnt<6||cnt>15||!Number.isInteger(cap)||cap<4||cap>10||cnt*cap<60)return err('모둠 수 6~15개, 모둠별 4~10명, 총 수용 인원 60명 이상으로 설정해 주세요.');
    const people=await records(s,'people/'),groups=Array.from({length:cnt},(_,i)=>({id:'g'+(i+1),label:(i+1)+'모둠',capacity:cap}));if(people.some(p=>!groups.some(g=>g.id===p.group)||people.filter(x=>x.group===p.group).length>cap))return err('현재 인원이 속한 모둠을 삭제하거나 인원 이하로 축소할 수 없습니다.');
    await put(s,'settings',{mode,groups,updatedAt:new Date().toISOString()});return js({ok:true,mode,groups});
 }
 if(op==='admin-transfer'&&req.method==='POST'){
    if(who.role!=='admin')return err('운영자만 가능합니다.',403);const b=await bodyJSON(req),person=await load(s,'people/'+b.id),st=await settings(s),g=st.groups.find(x=>x.id===b.group);if(!person||!g)return err('참가자나 모둠을 찾을 수 없습니다.');const people=await records(s,'people/');if(people.filter(x=>x.group===g.id).length>=g.capacity)return err('해당 모둠은 정원입니다.');person.group=g.id;await put(s,'people/'+person.id,person);const post=await load(s,'posts/'+person.id);if(post){post.group=g.id;await put(s,'posts/'+person.id,post);}return js({ok:true});
 }
 if(op==='admin-users'&&req.method==='GET'){
    if(who.role!=='admin')return err('운영자만 가능합니다.',403);const people=await records(s,'people/'),posts=await records(s,'posts/'),comments=await records(s,'comments/');return js({users:people.map(({id,name,school,group,joinedAt})=>({id,name,school,group,joinedAt,submitted:posts.some(p=>p.authorId===id),feedback:comments.filter(c=>c.authorId===id).length})),total:people.length});
 }
 if(op==='deck-start'&&req.method==='POST'){
    if(who.role!=='admin')return err('운영자만 가능합니다.',403);
    const b=await bodyJSON(req),size=Number(b.size),parts=Math.ceil(size/PART_SIZE);
    if(!Number.isSafeInteger(size)||size<100||size>LIMIT_PDF)return err('최대 12MB PDF 교안을 선택해 주세요.');const id=randomUUID();await put(s,'uploads/'+id,{fileId:id,owner:'admin',filename:'module1-slides.pdf',size,parts,status:'uploading',createdAt:Date.now()});return js({uploadId:id,parts,partSize:PART_SIZE});
 }
 if(op==='deck-part'&&req.method==='POST'){
    if(who.role!=='admin')return err('운영자만 가능합니다.',403);const id=url.searchParams.get('id'),n=Number(url.searchParams.get('n')),meta=await load(s,'uploads/'+id);if(!meta||meta.owner!=='admin'||meta.status!=='uploading'||!Number.isInteger(n)||n<0||n>=meta.parts)return err('업로드 오류',403);const data=await req.arrayBuffer();if(data.byteLength<1||data.byteLength>PART_SIZE)return err('크기 오류');await s.set('pdfparts/'+id+'/'+n,data);return js({ok:true});
 }
 if(op==='deck-finish'&&req.method==='POST'){
    if(who.role!=='admin')return err('운영자만 가능합니다.',403);const b=await bodyJSON(req),meta=await load(s,'uploads/'+b.uploadId);if(!meta||meta.owner!=='admin')return err('업로드 오류',403);
    try{const bytes=merge(await readPDFParts(s,meta));const pdf=await PDFDocument.load(bytes);if(pdf.getPageCount()!==19)return err('현재 교안은 19장입니다. 19쪽 PDF를 업로드해 주세요.');meta.status='ready';await put(s,'uploads/'+meta.fileId,meta);await put(s,'deck-meta',{uploadId:meta.fileId,size:meta.size,pages:19});return js({ok:true});}catch(e){return err('교안 PDF 검증 오류: '+e.message);}
 }
 if(op==='deck-info'&&req.method==='GET'){const d=await load(s,'deck-meta');return js({exists:!!d,pages:d?.pages||0});}
 if(op==='deck'&&req.method==='GET'){const d=await load(s,'deck-meta');if(!d)return err('아직 운영자가 교안 PDF를 등록하지 않았습니다.',404);const meta=await load(s,'uploads/'+d.uploadId);return respondPDF(merge(await readPDFParts(s,meta)));}
 return err('지원하지 않는 요청입니다.',404);
}