import { scan } from "./_lib/scan.js";
export default async function handler(req,res){
if(req.method!=="POST"){res.status(405).json({error:"method_not_allowed"});return;}
const b=req.body; if(!b||typeof b!=="object"){res.status(400).json({error:"invalid_request"});return;}
const {code,language}=b;
if(typeof code!=="string"||!code.trim()){res.status(400).json({error:"invalid_request"});return;}
res.status(200).json(scan(code,typeof language==="string"?language:undefined));
}
