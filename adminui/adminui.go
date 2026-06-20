// Package adminui exposes the auth plugin's admin configuration UI for Go hosts.
package adminui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
)

const (
	defaultAdminBasePath = "/admin/auth/config"
	defaultDescribePath  = "/api/admin/auth/config"
	defaultValidatePath  = "/api/admin/auth/config/validate"
)

// Options configures the embedded auth admin configuration UI for a host app.
type Options struct {
	AdminBasePath string
	DescribePath  string
	ValidatePath  string
}

// Handler serves the auth admin configuration page under a host-owned prefix.
func Handler(options Options) http.Handler {
	options = normalizeOptions(options)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cleanPath(r.URL.Path) == strings.TrimRight(options.AdminBasePath, "/") && !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, ensureTrailingSlash(options.AdminBasePath), http.StatusMovedPermanently)
			return
		}
		html, err := ConfigHTML(options)
		if err != nil {
			http.Error(w, "auth admin config unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(html)
	})
}

// ConfigHTML renders the auth admin configuration page with host endpoints.
func ConfigHTML(options Options) ([]byte, error) {
	options = normalizeOptions(options)
	payload, err := json.Marshal(map[string]string{
		"adminBasePath": options.AdminBasePath,
		"describePath":  options.DescribePath,
		"validatePath":  options.ValidatePath,
	})
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(configHTMLTemplate, payload)), nil
}

func normalizeOptions(options Options) Options {
	if strings.TrimSpace(options.AdminBasePath) == "" {
		options.AdminBasePath = defaultAdminBasePath
	}
	if strings.TrimSpace(options.DescribePath) == "" {
		options.DescribePath = defaultDescribePath
	}
	if strings.TrimSpace(options.ValidatePath) == "" {
		options.ValidatePath = defaultValidatePath
	}
	options.AdminBasePath = "/" + strings.Trim(strings.TrimSpace(options.AdminBasePath), "/")
	options.DescribePath = "/" + strings.Trim(strings.TrimSpace(options.DescribePath), "/")
	options.ValidatePath = "/" + strings.Trim(strings.TrimSpace(options.ValidatePath), "/")
	return options
}

func cleanPath(value string) string {
	return path.Clean("/" + strings.TrimPrefix(value, "/"))
}

func ensureTrailingSlash(value string) string {
	if strings.HasSuffix(value, "/") {
		return value
	}
	return value + "/"
}

const configHTMLTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authentication Settings</title>
  <style>
    :root { color-scheme: light; --bg:#f7f8fa; --panel:#fff; --text:#172033; --muted:#5d6778; --line:#dce2ea; --accent:#0f766e; --danger:#b42318; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font:14px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(1080px,100%%); margin:0 auto; padding:24px; }
    header { display:flex; justify-content:space-between; gap:16px; align-items:center; margin-bottom:18px; }
    h1 { margin:0; font-size:24px; }
    h2 { margin:0 0 12px; font-size:16px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; margin-bottom:14px; }
    .controls { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
    label { display:grid; gap:6px; color:var(--muted); font-weight:600; }
    input, select { width:100%%; border:1px solid var(--line); border-radius:6px; padding:9px 10px; font:inherit; background:#fff; color:var(--text); }
    input[type="checkbox"] { width:auto; justify-self:start; }
    small { color:var(--muted); font-weight:400; }
    button { border:0; border-radius:6px; padding:10px 14px; font:inherit; font-weight:700; color:#fff; background:var(--accent); cursor:pointer; }
    button:disabled { opacity:.65; cursor:wait; }
    .status { min-height:20px; color:var(--muted); }
    .diagnostics { display:grid; gap:8px; margin-top:12px; }
    .diagnostic { border-left:4px solid var(--accent); background:#eef7f5; padding:8px 10px; }
    .diagnostic.error { border-color:var(--danger); background:#fff1f0; color:#7f1d1d; }
    @media (max-width: 760px) { .controls { grid-template-columns:1fr; } header { align-items:flex-start; flex-direction:column; } }
  </style>
</head>
<body data-auth-admin-config-ui="1">
  <main>
    <header>
      <div>
        <h1>Authentication Settings</h1>
        <p class="status" id="status">Loading authentication configuration...</p>
      </div>
      <button id="save" type="button">Save Settings</button>
    </header>
    <form id="settings"></form>
    <div class="diagnostics" id="diagnostics"></div>
  </main>
  <script>window.__WORKFLOW_AUTH_CONFIG_UI__=%s;</script>
  <script>
const config=window.__WORKFLOW_AUTH_CONFIG_UI__;
const form=document.getElementById("settings");
const statusEl=document.getElementById("status");
const diagnosticsEl=document.getElementById("diagnostics");
const saveButton=document.getElementById("save");
let controls=[];
function setStatus(text){statusEl.textContent=text||"";}
function renderDiagnostics(items){
  diagnosticsEl.innerHTML="";
  for(const item of items||[]){
    const div=document.createElement("div");
    div.className="diagnostic "+(item.severity==="error"?"error":"");
    div.textContent=(item.field?item.field+": ":"")+(item.message||"");
    diagnosticsEl.appendChild(div);
  }
}
function controlValue(control){
  const key=control.config_key||control.key;
  const el=form.elements[key];
  if(!el){return undefined;}
  if(el.type==="checkbox"){return el.checked;}
  if(el.value===""){return undefined;}
  return el.value;
}
function renderControl(control){
  const key=control.config_key||control.key;
  const label=document.createElement("label");
  const title=document.createElement("span");
  title.textContent=control.label||key;
  label.appendChild(title);
  let input;
  if(control.input_type==="select"&&Array.isArray(control.options)){
    input=document.createElement("select");
    for(const option of control.options){
      const opt=document.createElement("option");
      opt.value=option.value||option.label||"";
      opt.textContent=option.label||option.value||"";
      input.appendChild(opt);
    }
  }else{
    input=document.createElement("input");
    input.type=inputType(control.input_type);
  }
  input.name=key;
  input.disabled=Boolean(control.disabled_reason);
  if(input.type==="checkbox"){input.checked=Boolean(control.value);}
  else if(control.value!==undefined&&control.value!==null){input.value=String(control.value);}
  label.appendChild(input);
  const help=control.disabled_reason||control.help_text||control.description||"";
  if(help){const small=document.createElement("small");small.textContent=help;label.appendChild(small);}
  return label;
}
function inputType(value){
  if(value==="toggle"){return "checkbox";}
  if(value==="secret"){return "password";}
  return value||"text";
}
function render(payload){
  form.innerHTML="";
  controls=[];
  for(const group of payload.groups||[]){
    const section=document.createElement("section");
    section.className="panel";
    const h2=document.createElement("h2");
    h2.textContent=group.title||group.label||"Settings";
    section.appendChild(h2);
    const grid=document.createElement("div");
    grid.className="controls";
    for(const control of group.controls||[]){
      controls.push(control);
      grid.appendChild(renderControl(control));
    }
    section.appendChild(grid);
    form.appendChild(section);
  }
  renderDiagnostics([...(payload.warnings||[]),...(payload.errors||[])]);
}
async function load(){
  const response=await fetch(config.describePath,{credentials:"same-origin"});
  if(!response.ok){throw new Error("Failed to load authentication settings.");}
  render(await response.json());
  setStatus("Authentication configuration loaded.");
}
saveButton.addEventListener("click",async()=>{
  saveButton.disabled=true;
  try{
    const desired_config={};
    for(const control of controls){
      const key=control.config_key||control.key;
      const value=controlValue(control);
      if(value!==undefined){desired_config[key]=value;}
    }
    const response=await fetch(config.validatePath,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({desired_config})});
    const payload=await response.json();
    renderDiagnostics([...(payload.warnings||[]),...(payload.errors||[])]);
    if(!response.ok||((payload.errors||[]).length>0)){throw new Error("Authentication settings need attention.");}
    setStatus("Authentication settings validated.");
  }catch(err){setStatus(err.message);}
  finally{saveButton.disabled=false;}
});
load().catch(err=>setStatus(err.message));
  </script>
</body>
</html>`
