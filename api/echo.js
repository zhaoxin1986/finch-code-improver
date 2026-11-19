export default function handler(req,res){
  console.log(JSON.stringify({
    at:new Date().toISOString(),
    method:req.method,
    url:req.url,
    host:req.headers.host,
    ua:req.headers["user-agent"],
    xff:req.headers["x-forwarded-for"],
    finch:req.headers["x-platform-key-id"]||null
  }));
  res.status(200).json({status:"ok",echo:{method:req.method,url:req.url}});
}
