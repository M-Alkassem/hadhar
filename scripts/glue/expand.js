// One item per outgoing message.
const out = [];
for (const it of $input.all()) for (const m of it.json.messages || []) out.push({ json: m });
return out;
