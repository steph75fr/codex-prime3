// Cloudflare Worker — no credentials in source or browser.
const LIMITS = {name:120,url:2048,type:40,desc:4000,access:1000,verified:32,source:500,category:80};
const headers={"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"};
const json=(data,status=200,extra={})=>new Response(JSON.stringify(data),{status,headers:{...headers,...extra}});
const fail=(message,status=400)=>json({error:message},status);
const keyFor=id=>"tools/"+id+".json";
const commentPrefix=id=>"comments/"+id+"/";
const idOK=id=>typeof id==="string" && /^tool-[0-9]{3}$/.test(id);
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
const badKey=k=>!/^([a-zA-Z][a-zA-Z0-9_-]{0,49})$/.test(k)||["__proto__","constructor","prototype"].includes(k);
const isObject=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
const fieldKeys=["name","url","type","desc","access","verified","source","category"];
const protectedKeys=new Set(["toolId","version","updatedAt","comments","categoryLabel"]);
function checkValue(value,depth=0){
  if(depth>3)return false;
  if(typeof value==="boolean")return true;
  if(typeof value==="number")return Number.isFinite(value);
  if(typeof value==="string")return value.length<=4000;
  if(Array.isArray(value))return value.length<=50&&value.every(v=>checkValue(v,depth+1));
  if(isObject(value))return Object.keys(value).length<=30&&Object.entries(value).every(([k,v])=>!badKey(k)&&checkValue(v,depth+1));
  return false;
}
function validate(data){
  if(!isObject(data))throw Error("Fiche JSON attendue");
  const allowed=new Set([...fieldKeys,"toolId","version","updatedAt","customFields"]);
  if(Object.keys(data).some(k=>!allowed.has(k)))throw Error("Champ inconnu : utiliser customFields");
  for(const k of fieldKeys){
    if(typeof data[k]!=="string"||data[k].length>LIMITS[k])throw Error("Champ invalide : "+k);
  }
  if(!data.name.trim()||!data.category.trim()||!data.type.trim())throw Error("Nom, catégorie et type requis");
  try{const u=new URL(data.url);if(!["http:","https:"].includes(u.protocol))throw Error();}catch{throw Error("URL http/https requise")}
  if(data.verified&&!/^\d{4}-\d{2}-\d{2}$/.test(data.verified))throw Error("Date ISO YYYY-MM-DD requise");
  const custom=data.customFields??{};
  if(!isObject(custom)||Object.keys(custom).length>30)throw Error("Champs personnalisés invalides");
  for(const [key,val] of Object.entries(custom)){
    if(badKey(key)||fieldKeys.includes(key)||!isObject(val)||!["string","number","boolean","date","list"].includes(val.type))throw Error("Champ personnalisé incorrect : "+key);
    const v=val.value;
    if(val.type==="string"&&(typeof v!=="string"||v.length>4000))throw Error("Texte invalide : "+key);
    if(val.type==="number"&&(typeof v!=="number"||!Number.isFinite(v)))throw Error("Nombre invalide : "+key);
    if(val.type==="boolean"&&typeof v!=="boolean")throw Error("Booléen invalide : "+key);
    if(val.type==="date"&&(typeof v!=="string"||!/^\d{4}-\d{2}-\d{2}$/.test(v)))throw Error("Date invalide : "+key);
    if(val.type==="list"&&(!Array.isArray(v)||v.length>50||!v.every(x=>typeof x==="string"&&x.length<=500)))throw Error("Liste invalide : "+key);
  }
  if(JSON.stringify(data).length>32000)throw Error("Fiche trop volumineuse");
  return {toolId:data.toolId,...Object.fromEntries(fieldKeys.map(k=>[k,data[k]])),customFields:custom};
}
function accessConfigured(env){
  return !!(env.ACCESS_TEAM_DOMAIN&&env.ACCESS_AUD&&/^https:\/\/[a-z0-9.-]+$/i.test(env.ACCESS_TEAM_DOMAIN)&&env.ACCESS_AUD.length>10);
}
function b64url(s){const raw=atob(s.replace(/-/g,"+").replace(/_/g,"/"));return Uint8Array.from(raw,c=>c.charCodeAt(0))}
async function authenticated(request,env){
  if(!accessConfigured(env))return false;
  const token=request.headers.get("Cf-Access-Jwt-Assertion");
  if(!token)return false;
  try{
    const parts=token.split(".");if(parts.length!==3)return false;
    const head=JSON.parse(new TextDecoder().decode(b64url(parts[0])));
    const payload=JSON.parse(new TextDecoder().decode(b64url(parts[1])));
    if(head.alg!=="RS256"||!head.kid)return false;
    const now=Math.floor(Date.now()/1000);
    const domain=env.ACCESS_TEAM_DOMAIN.replace(/\/$/,"");
    if(payload.iss!==domain||!(Array.isArray(payload.aud)?payload.aud.includes(env.ACCESS_AUD):payload.aud===env.ACCESS_AUD)||typeof payload.exp!=="number"||payload.exp<=now||typeof payload.iat!=="number"||payload.iat>now+60||(payload.nbf&&payload.nbf>now))return false;
    const jwks=await fetch(domain+"/cdn-cgi/access/certs");
    if(!jwks.ok)return false;
    const keys=(await jwks.json()).keys||[];
    const jwk=keys.find(k=>k.kid===head.kid&&k.kty==="RSA"&&(k.use==="sig"||!k.use));
    if(!jwk)return false;
    const publicKey=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5",publicKey,b64url(parts[2]),new TextEncoder().encode(parts[0]+"."+parts[1]));
  }catch{return false}
}
async function allKeys(bucket,prefix){
  let cursor;const keys=[];
  do{
    const page=await bucket.list({prefix,cursor,limit:1000});
    keys.push(...page.objects.map(x=>x.key));cursor=page.truncated?page.cursor:undefined;
  }while(cursor);
  return keys;
}
async function readTool(env,id){
  const obj=await env.OUTILS_BUCKET.get(keyFor(id));
  return obj?{item:await obj.json(),etag:obj.httpEtag}:null;
}
async function handle(request,env){
  const u=new URL(request.url),path=u.pathname;
  if(!env.OUTILS_BUCKET)return fail("Binding R2 absent",503);
  if(request.method==="GET"&&path==="/api/status"){
    const enabled=accessConfigured(env);
    return json({editingEnabled:enabled&&await authenticated(request,env),protectionConfigured:enabled});
  }
  if(request.method==="GET"&&path==="/api/tools"){
    const toolKeys=await allKeys(env.OUTILS_BUCKET,"tools/");
    const commentKeys=await allKeys(env.OUTILS_BUCKET,"comments/");
    const [tools,comments]=await Promise.all([
      Promise.all(toolKeys.map(async key=>{const o=await env.OUTILS_BUCKET.get(key);return o?o.json():null})),
      Promise.all(commentKeys.map(async key=>{const o=await env.OUTILS_BUCKET.get(key);return o?o.json():null}))
    ]);
    return json({tools:tools.filter(Boolean),comments:comments.filter(Boolean)});
  }
  if(!["POST","PUT"].includes(request.method))return fail("Route inconnue",404);
  if(!await authenticated(request,env))return fail("Authentification Cloudflare Access requise ou non configurée",403);
  let body;try{if(Number(request.headers.get("Content-Length")||0)>100000)throw Error();body=await request.json();}catch{return fail("JSON invalide ou trop grand")}
  if(path==="/api/admin/initialize"&&request.method==="POST"){
    if(!Array.isArray(body.tools)||body.tools.length!==43)return fail("Initialisation : exactement 43 fiches requises");
    const ids=new Set(),validated=[];
    try{for(const t of body.tools){
      if(!idOK(t.toolId)||ids.has(t.toolId))throw Error("ID fixe invalide ou doublon");
      ids.add(t.toolId);validated.push(validate(t));
    }}catch(e){return fail(e.message)}
    const results=[];
    for(const t of validated){
      const key=keyFor(t.toolId),existing=await env.OUTILS_BUCKET.head(key);
      if(existing){results.push({toolId:t.toolId,status:"exists"});continue}
      const item={...t,version:1,updatedAt:new Date().toISOString()};
      const put=await env.OUTILS_BUCKET.put(key,JSON.stringify(item),{onlyIf:{etagDoesNotMatch:"*"},httpMetadata:{contentType:"application/json"}});
      results.push({toolId:t.toolId,status:put?"created":"exists"});
    }
    return json({results,created:results.filter(r=>r.status==="created").length});
  }
  const match=path.match(/^\/api\/tools\/(tool-[0-9]{3})$/);
  if(match&&request.method==="PUT"){
    const id=match[1];if(body.toolId!==id)return fail("Identifiant immuable");
    let data;try{data=validate(body)}catch(e){return fail(e.message)}
    const current=await readTool(env,id);if(!current)return fail("Fiche absente",404);
    if(!Number.isSafeInteger(body.version)||body.version!==current.item.version)return fail("Conflit de version : recharger avant modification",409);
    const next={...data,version:current.item.version+1,updatedAt:new Date().toISOString()};
    const result=await env.OUTILS_BUCKET.put(keyFor(id),JSON.stringify(next),{onlyIf:{etagMatches:current.etag},httpMetadata:{contentType:"application/json"}});
    if(!result)return fail("Conflit concurrent : aucune donnée écrasée",409);
    return json({tool:next});
  }
  const commentMatch=path.match(/^\/api\/tools\/(tool-[0-9]{3})\/comments$/);
  if(commentMatch&&request.method==="POST"){
    const id=commentMatch[1];if(!await env.OUTILS_BUCKET.head(keyFor(id)))return fail("Fiche absente",404);
    if(typeof body.text!=="string"||!body.text.trim()||body.text.length>2000)return fail("Commentaire requis (2000 caractères maximum)");
    const comment={commentId:crypto.randomUUID(),toolId:id,text:body.text.trim(),createdAt:new Date().toISOString()};
    await env.OUTILS_BUCKET.put(commentPrefix(id)+comment.commentId+".json",JSON.stringify(comment),{httpMetadata:{contentType:"application/json"}});
    return json({comment},201);
  }
  return fail("Route inconnue",404);
}
export default {async fetch(request,env){
  try{return await handle(request,env)}catch(e){console.error("Worker failure",e);return fail("Erreur interne",500)}
}};
