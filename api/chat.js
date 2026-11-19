import { verifyIncomingSignature, signOutgoingResponse, readRawBody } from "./_lib/hmac.js";
import { scan, scanToText, extractCodeFromText } from "./_lib/scan.js";
export const config={api:{bodyParser:false}};
export default async function handler(req,res){
if(req.method!=="POST"){res.status(405).end();return;}
const s=Buffer.from(process.env.FINCH_V2_REQUEST_SECRET||"","base64url"),kid=process.env.FINCH_V2_KEY_ID;
if(!process.env.FINCH_V2_REQUEST_SECRET||!kid){res.status(500).json({error:"server_misconfigured"});return;}
const raw=await readRawBody(req);
const v=verifyIncomingSignature({method:"POST",pathWithQuery:req.url,rawBody:raw,headers:req.headers,requestSecretBytes:s});
if(!v.ok){res.status(401).json({error:"invalid_signature",reason:v.reason});return;}
let p;try{p=JSON.parse(raw.toString("utf8"));}catch{res.status(400).json({error:"invalid_json"});return;}
const parts=p?.input?.content;
const text=Array.isArray(parts)?parts.filter(x=>x?.type==="text").map(x=>x.text).join("\n"):"";
let out;
if(!text.trim())out={protocol_version:"2.0",invocation_id:p.invocation_id,status:"failed",error:{code:"invalid_input",message:"no text"}};
else{const r=scan(extractCodeFromText(text));out={protocol_version:"2.0",invocation_id:p.invocation_id,status:"completed",message:{role:"agent",content:[{type:"text",text:scanToText(r)}]},artifacts:[],completed_at:new Date().toISOString()};}
const body=Buffer.from(JSON.stringify(out));
const h=signOutgoingResponse({method:"POST",pathWithQuery:req.url,responseBodyBytes:body,requestSecretBytes:s,keyId:kid});
res.writeHead(200,{"Content-Type":"application/json",...h});res.end(body);
}
