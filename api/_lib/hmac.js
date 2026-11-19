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
