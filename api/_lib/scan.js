export function scan(code,language){
const lines=code.split("\n"),f=[];
lines.forEach((line,i)=>{const n=i+1;
if(/console\.log\(/.test(line))f.push({severity:"low",line:n,issue:"遗留 console.log",suggestion:"上线前移除"});
if(/\bvar\s/.test(line))f.push({severity:"low",line:n,issue:"使用了 var",suggestion:"改用 const/let"});
if(/[^=!<>]==[^=]/.test(line)&&!/===|!==/.test(line))f.push({severity:"medium",line:n,issue:"宽松相等 ==",suggestion:"改用 ==="});});
if(!f.length)f.push({severity:"info",line:0,issue:"未发现明显问题",suggestion:"—"});
return {summary:`扫描 ${lines.length} 行，找到 ${f.filter(x=>x.severity!=="info").length} 项`,findings:f.slice(0,15)};
}
export function scanToText(r){const o=[r.summary,""];r.findings.forEach((x,i)=>{o.push(`${i+1}. [${x.severity}] 第${x.line}行：${x.issue}`);o.push(`   建议：${x.suggestion}`);});return o.join("\n");}
export function extractCodeFromText(t){const m=t.match(/```(?:[a-z]*\n)?([\s\S]*?)```/i);return m?m[1].trim():t.trim();}
