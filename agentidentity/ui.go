package agentidentity

import (
	"encoding/json"
	"fmt"
)

func managementHTML(o ManagementOptions, tenants []TenantConfig) ([]byte, error) {
	payload, err := json.Marshal(struct {
		APIPath string         `json:"api_path"`
		Tenants []TenantConfig `json:"tenants"`
	}{o.Path, tenants})
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(managementTemplate, payload)), nil
}

const managementTemplate = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Agent access</title>
<style>body{font:15px/1.5 system-ui;background:#f7f8fa;color:#172033;margin:0}main{max-width:880px;padding:24px;margin:auto}section{background:white;border:1px solid #c4cad5;border-radius:8px;padding:20px;margin:16px 0}label{display:block;margin:10px 0}input,select,textarea,button{font:inherit;max-width:100%%;box-sizing:border-box;padding:8px}input[type=text],input[type=url],textarea{width:100%%}button{background:#0f766e;color:white;border:0;border-radius:4px;cursor:pointer}textarea{min-height:140px}small{display:block;color:#414c61}pre{white-space:pre-wrap;overflow-wrap:anywhere}#boundary,#grants{overflow-wrap:anywhere}ul{padding-left:24px}:focus-visible{outline:3px solid #2563eb;outline-offset:3px}</style></head>
<body data-agent-grant-admin="1"><main><h1>Agent access</h1><p>Approve a separate assistant for a preview site. Access expires automatically and can be revoked here. Your personal account and login stay separate.</p>
<section><h2>Approve access</h2><form id="grant-form">
<label for="tenant">Preview site</label><select id="tenant" required></select><p id="boundary"></p>
<label>Assistant subject <input id="subject" type="text" required maxlength="128" placeholder="agent-preview-assistant"></label>
<label>Assertion issuer <input id="issuer" type="url" required placeholder="https://workload.example.com"></label>
<label>Public key identifier <input id="key-id" type="text" required maxlength="128"></label>
<label>Public workload key <textarea id="public-key" required placeholder="-----BEGIN PUBLIC KEY-----"></textarea></label><small>Use the public key from the approved protected workload. Its private key stays in the configured protected store; it is never entered here.</small>
<label for="days">Expires in</label><select id="days"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option></select>
<fieldset><legend>Permissions</legend><div id="permissions"></div></fieldset>
<label><input id="confirmed" type="checkbox" required> I approve this assistant, site, permissions and expiry.</label><button type="submit">Approve access</button></form></section>
<section><h2>Current grants</h2><button id="reload" type="button">Refresh</button><ul id="grants"></ul></section><p id="status" role="status" aria-live="polite"></p>
<script>const config=%s;
const statusEl=document.getElementById('status'),tenantEl=document.getElementById('tenant');
const labels={'admin:multisite.pages:read':'Read saved pages','admin:multisite.pages:history:read':'Read saved history','admin:multisite.pages:update':'Edit the listed page bodies only','admin:multisite.preview:read':'View this protected preview'};
for(const t of config.tenants){const o=document.createElement('option');o.value=String(t.tenant_id);o.textContent='Preview tenant '+t.tenant_id;tenantEl.append(o)}
function selected(){return config.tenants.find(t=>String(t.tenant_id)===tenantEl.value)}
function renderBoundary(){const t=selected();document.getElementById('boundary').textContent='API: '+t.api_audience+' · Editable pages: '+(t.update_page_ids||[]).join(', ')+(t.preview?' · Preview: '+t.preview.origin+' · Allowed routes and assets: '+t.preview.paths.join(', '):'');const box=document.getElementById('permissions');box.replaceChildren();for(const scope of t.scopes){const label=document.createElement('label'),check=document.createElement('input');check.type='checkbox';check.value=scope;check.checked=scope.endsWith(':read')&&!scope.includes('.preview:');label.append(check,document.createTextNode(' '+labels[scope]));box.append(label)}}
async function request(path,method='GET',body){const r=await fetch(path,{method,credentials:'same-origin',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});if(!r.ok)throw new Error('Access request failed ('+r.status+').');return r.status===204?null:r.json()}
async function load(){const list=document.getElementById('grants');list.replaceChildren();for(const g of await request(config.api_path)){const item=document.createElement('li');item.append(document.createTextNode(g.subject+' · tenant '+g.tenant_id+' · expires '+new Date(g.expires_at).toLocaleString()+' · '+(g.revoked?'revoked':new Date(g.expires_at).getTime()<=Date.now()?'expired':'active')+' · '+g.scopes.map(s=>labels[s]||s).join(', ')));if(!g.revoked){const button=document.createElement('button');button.type='button';button.textContent='Revoke';button.addEventListener('click',async()=>{if(!confirm('Revoke '+g.subject+' for tenant '+g.tenant_id+'?'))return;try{await request(config.api_path+'/revoke','POST',{id:g.id,expected_version:g.version,confirmed:true});statusEl.textContent='Access revoked.';await load()}catch(e){statusEl.textContent=e.message}});item.append(document.createTextNode(' '),button)}list.append(item)}}
tenantEl.addEventListener('change',renderBoundary);document.getElementById('reload').addEventListener('click',()=>load().catch(e=>statusEl.textContent=e.message));
document.getElementById('grant-form').addEventListener('submit',async e=>{e.preventDefault();const t=selected(),scopes=[...document.querySelectorAll('#permissions input:checked')].map(x=>x.value);if(!scopes.length){statusEl.textContent='Select at least one permission.';return}const body={subject:document.getElementById('subject').value,assertion_issuer:document.getElementById('issuer').value,key_id:document.getElementById('key-id').value,public_key_pem:document.getElementById('public-key').value,tenant_id:t.tenant_id,api_audience:t.api_audience,expires_at:new Date(Date.now()+Number(document.getElementById('days').value)*86400000).toISOString(),scopes,update_page_ids:scopes.includes('admin:multisite.pages:update')?t.update_page_ids:[],preview:scopes.includes('admin:multisite.preview:read')?t.preview:null,confirmed:document.getElementById('confirmed').checked};try{await request(config.api_path,'POST',body);statusEl.textContent='Scoped access approved. Private key custody and workload activation remain with the approved operator.';await load()}catch(e){statusEl.textContent=e.message}});
renderBoundary();load().catch(e=>statusEl.textContent=e.message);
</script></main></body></html>`
