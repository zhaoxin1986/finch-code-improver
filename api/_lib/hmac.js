import crypto from "node:crypto";
function sha256Hex(b){return crypto.createHash("sha256").update(b).digest("hex");}
function canon({method,pathWithQuery,timestamp,nonce,rawBody}){return [method,pathWithQuery,timestamp,nonce,sha256Hex(rawBody)].join("\n");}
function hmacHex(k,m){return crypto.createHmac("sha256",k).update(m).digest("hex");}
export function verifyIncomingSignature({method,pathWithQuery,rawBody,headers,requestSecretBytes,maxSkewSeconds=300}){
const kid=headers["x-platform-key-id"],ts=headers["x-platform-timestamp"],nc=headers["x-platform-nonce"],sg=headers["x-platform-signature"];
if(!kid||!ts||!nc||!sg)return{ok:false,reason:"missing_headers"};
if(Math.abs(Math.floor(Date.now()/1000)-Number(ts))>maxSkewSeconds)return{ok:false,reason:"skew"};
const exp="v1="+hmacHex(requestSecretBytes,canon({method,pathWithQuery,timestamp:ts,nonce:nc,rawBody}));
const a=Buffer.from(exp),b=Buffer.from(sg);
return a.length===b.length&&crypto.timingSafeEqual(a,b)?{ok:true,keyId:kid}:{ok:false,reason:"mismatch"};
}
export function signOutgoingResponse({method,pathWithQuery,responseBodyBytes,requestSecretBytes,keyId}){
const ts=String(Math.floor(Date.now()/1000)),nc=crypto.randomBytes(16).toString("hex");
const sig="v1="+hmacHex(requestSecretBytes,canon({method,pathWithQuery,timestamp:ts,nonce:nc,rawBody:responseBodyBytes}));
return{"X-Agent-Key-Id":keyId,"X-Agent-Timestamp":ts,"X-Agent-Nonce":nc,"X-Agent-Signature":sig};
}
export function readRawBody(req){return new Promise((res,rej)=>{const c=[];req.on("data",x=>c.push(x));req.on("end",()=>res(Buffer.concat(c)));req.on("error",rej);});}

// TEMP diagnostic: find which canonicalization variant matches an incoming signature
export function diagnoseSignature({method,pathWithQuery,rawBody,headers,secretRaw}){
const sg=headers["x-platform-signature"],ts=headers["x-platform-timestamp"],nc=headers["x-platform-nonce"]||"";
if(!sg||!ts)return "no_signature";
const pathOnly=(pathWithQuery||"").split("?")[0];
const secrets=[["b64url",Buffer.from(secretRaw||"","base64url")],["utf8",Buffer.from(secretRaw||"","utf8")]];
const bodies=[["sha256hex",sha256Hex(rawBody)],["sha256b64",crypto.createHash("sha256").update(rawBody).digest("base64")],["raw",rawBody.toString("utf8")]];
const paths=[["full",pathWithQuery],["pathOnly",pathOnly],["empty",""]];
const methods=[["method",method],["lower",method.toLowerCase()],["upper",method.toUpperCase()]];
for(const [sn,sb] of secrets)for(const [bn,bh] of bodies)for(const [pn,pv] of paths)for(const [mn,mv] of methods){
  const msg=[mv,pv,ts,nc,bh].join("\n");
  const sig="v1="+hmacHex(sb,msg);
  if(sig===sg)return `${sn}/${bn}/${pn}/${mn}/prefix`;
  if(sig.slice(3)===sg)return `${sn}/${bn}/${pn}/${mn}/noprefix`;
}
return "no_variant_matched";
}

// TEMP diagnostic v2: wider matrix, includes callback secret and separators
export function diagnoseSignature2({method,pathWithQuery,rawBody,headers,secretRaw,altSecretRaw}){
const sg=headers["x-platform-signature"],ts=headers["x-platform-timestamp"],nc=headers["x-platform-nonce"]||"",kid=headers["x-platform-key-id"]||"";
if(!sg||!ts)return "no_signature";
const pathOnly=(pathWithQuery||"").split("?")[0];
const keys=[["req:raw",Buffer.from(secretRaw||"","utf8")],["req:b64url",Buffer.from(secretRaw||"","base64url")],["req:b64",Buffer.from(secretRaw||"","base64")],["cb:raw",Buffer.from(altSecretRaw||"","utf8")],["cb:b64url",Buffer.from(altSecretRaw||"","base64url")]];
const bodies=[["sha256hex",sha256Hex(rawBody)],["sha256b64",crypto.createHash("sha256").update(rawBody).digest("base64")],["empty",""]];
const paths=[["full",pathWithQuery],["pathOnly",pathOnly]];
const methods=[["GET",method],["get",method.toLowerCase()]];
const seps=[["nl","\n"],["space"," "],["pipe","|"]];
const orders=[["m,p,t,n,b",(m,p,t,n,b)=>[m,p,t,n,b]],["t,n,m,p,b",(m,p,t,n,b)=>[t,n,m,p,b]],["k,m,p,t,n,b",(m,p,t,n,b)=>[kid,m,p,t,n,b]],["m,p,t,n,k,b",(m,p,t,n,b)=>[m,p,t,n,kid,b]]];
for(const [kn,k] of keys){
  if(!k.length)continue;
  for(const [bn,b] of bodies)for(const [pn,p] of paths)for(const [mn,m] of methods)for(const [sn,sep] of seps)for(const [on,of] of orders){
    const msg=of(m,p,ts,nc,b).join(sep);
    const sig="v1="+hmacHex(k,msg);
    if(sig===sg)return kn+"/"+bn+"/"+pn+"/"+mn+"/"+sn+"/"+on;
    if(sig.slice(3)===sg)return kn+"/"+bn+"/"+pn+"/"+mn+"/"+sn+"/"+on+"/noprefix";
  }
}
return "no_variant_matched";
}
