import { verifyIncomingSignature, signOutgoingResponse, readRawBody } from "./_lib/hmac.js";
export const config={api:{bodyParser:false}};
export default async function handler(req,res){
if(req.method!=="GET"){res.status(405).end();return;}
const s=Buffer.from(process.env.FINCH_V2_REQUEST_SECRET||"","base64url"),kid=process.env.FINCH_V2_KEY_ID;
if(!process.env.FINCH_V2_REQUEST_SECRET||!kid){res.status(500).json({error:"server_misconfigured"});return;}
const raw=await readRawBody(req);
const v=verifyIncomingSignature({method:"GET",pathWithQuery:req.url,rawBody:raw,headers:req.headers,requestSecretBytes:s});
if(!v.ok){res.status(401).json({error:"invalid_signature",reason:v.reason});return;}
const body=Buffer.from(JSON.stringify({status:"ready"}));
const h=signOutgoingResponse({method:"GET",pathWithQuery:req.url,responseBodyBytes:body,requestSecretBytes:s,keyId:kid});
res.writeHead(200,{"Content-Type":"application/json",...h});res.end(body);
}
