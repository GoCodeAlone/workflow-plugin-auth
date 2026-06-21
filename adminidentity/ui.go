package adminidentity

import (
	"encoding/json"
	"fmt"
)

func identityHTML(options Options) ([]byte, error) {
	payload, err := json.Marshal(map[string]string{
		"profilePath":       options.ProfilePath,
		"credentialsPath":   options.CredentialsPath,
		"passkeyBeginPath":  options.PasskeyBeginPath,
		"passkeyFinishPath": options.PasskeyFinishPath,
		"totpBeginPath":     options.TOTPBeginPath,
		"totpVerifyPath":    options.TOTPVerifyPath,
		"usersPath":         options.UsersPath,
		"setupRedeemPath":   options.SetupRedeemPath,
		"setupLoginPath":    options.SetupLoginPath,
	})
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(identityHTMLTemplate, payload)), nil
}

const identityHTMLTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Identity & Access</title>
  <style>
    body { margin:0; background:#f7f8fa; color:#172033; font:14px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(1040px,100%%); margin:0 auto; padding:24px; }
    section { background:#fff; border:1px solid #dce2ea; border-radius:8px; padding:18px; margin-bottom:14px; }
    h1 { margin:0 0 18px; font-size:24px; }
    h2 { margin:0 0 12px; font-size:16px; }
    button { border:0; border-radius:6px; padding:10px 14px; background:#0f766e; color:#fff; font-weight:700; cursor:pointer; }
    button[disabled] { opacity:.65; cursor:default; }
    .muted { color:#5d6778; }
  </style>
</head>
<body data-auth-identity-admin="1">
  <main>
    <h1>Identity & Access</h1>
    <section>
      <h2>My Profile</h2>
      <p id="profile" class="muted">Loading profile...</p>
      <form id="profileForm">
        <label>Display name <input id="displayName" name="display_name"></label>
        <label>Recovery email <input id="recoveryEmail" name="recovery_email" type="email"></label>
        <button type="submit">Save profile</button>
      </form>
      <p id="profileStatus" class="muted"></p>
    </section>
    <section>
      <h2>Sign-in & 2FA</h2>
      <p id="credentials" class="muted">Loading credentials...</p>
      <button id="addPasskey" type="button">Add passkey</button>
      <button id="beginTotp" type="button">Set up 2FA</button>
    </section>
    <section>
      <h2>Users</h2>
      <ul id="users" class="muted">Loading users...</ul>
      <form id="inviteForm">
        <label>Email <input name="email" type="email" required></label>
        <label>Display name <input name="display_name"></label>
        <label>Role <select name="role"><option value="tenant_editor">tenant_editor</option><option value="tenant_admin">tenant_admin</option><option value="super_admin">super_admin</option></select></label>
        <button type="submit">Add admin</button>
      </form>
      <p id="inviteStatus" class="muted"></p>
    </section>
  </main>
  <script>window.__WORKFLOW_AUTH_IDENTITY_UI__=%s;</script>
  <script>
const config=window.__WORKFLOW_AUTH_IDENTITY_UI__;
const profileEl=document.getElementById("profile");
const profileForm=document.getElementById("profileForm");
const profileStatus=document.getElementById("profileStatus");
const displayName=document.getElementById("displayName");
const recoveryEmail=document.getElementById("recoveryEmail");
const credentialsEl=document.getElementById("credentials");
const usersEl=document.getElementById("users");
const inviteForm=document.getElementById("inviteForm");
const inviteStatus=document.getElementById("inviteStatus");
const addPasskey=document.getElementById("addPasskey");
const beginTotp=document.getElementById("beginTotp");
function setTotpEnrollmentState(enrolled){
  beginTotp.disabled=Boolean(enrolled);
  beginTotp.textContent=enrolled?"2FA enabled":"Set up 2FA";
}
async function loadProfile(){
  const res=await fetch(config.profilePath,{credentials:"same-origin"});
  if(!res.ok){throw new Error("Profile unavailable");}
  const payload=await res.json();
  const user=payload.user||{};
  displayName.value=user.display_name||"";
  recoveryEmail.value=user.recovery_email||user.email||"";
  profileEl.textContent=[user.display_name,user.email].filter(Boolean).join(" · ")||"Profile loaded";
}
async function loadCredentials(){
  const res=await fetch(config.credentialsPath,{credentials:"same-origin"});
  if(!res.ok){throw new Error("Credentials unavailable");}
  const payload=await res.json();
  const credentials=Array.isArray(payload.credentials)?payload.credentials:[];
  const totpEnrolled=Boolean(payload.totp_enrolled)||credentials.some(credential=>String(credential.kind||"").toLowerCase()==="totp");
  setTotpEnrollmentState(totpEnrolled);
  const count=Number.isFinite(payload.count)?payload.count:credentials.length;
  credentialsEl.textContent=count+" credential(s)";
}
async function loadUsers(){
  const res=await fetch(config.usersPath,{credentials:"same-origin"});
  if(!res.ok){usersEl.textContent="Users unavailable";return;}
  const payload=await res.json();
  const users=payload.users||[];
  usersEl.replaceChildren();
  if(!users.length){usersEl.textContent="No users found";return;}
  for(const user of users){
    const item=document.createElement("li");
    item.textContent=(user.display_name||user.email)+" · "+user.role;
    usersEl.append(item);
  }
}
function b64urlToBuf(value){
  const base64=String(value||"").replace(/-/g,"+").replace(/_/g,"/");
  const padded=base64+"=".repeat((4-base64.length%%4)%%4);
  const raw=atob(padded);
  const bytes=new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++){bytes[i]=raw.charCodeAt(i);}
  return bytes.buffer;
}
function bufToB64url(value){
  const bytes=new Uint8Array(value);
  let raw="";
  for(const byte of bytes){raw+=String.fromCharCode(byte);}
  return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function webauthnCreationOptions(options){
  const parsed=typeof options==="string"?JSON.parse(options):options;
  const publicKey=parsed.publicKey||parsed;
  publicKey.challenge=b64urlToBuf(publicKey.challenge);
  if(publicKey.user&&publicKey.user.id){publicKey.user.id=b64urlToBuf(publicKey.user.id);}
  if(publicKey.excludeCredentials){for(const credential of publicKey.excludeCredentials){credential.id=b64urlToBuf(credential.id);}}
  return {publicKey};
}
function creationResponsePayload(credential){
  return {id:credential.id,type:credential.type,rawId:bufToB64url(credential.rawId),authenticatorAttachment:credential.authenticatorAttachment||"",response:{clientDataJSON:bufToB64url(credential.response.clientDataJSON),attestationObject:bufToB64url(credential.response.attestationObject)}};
}
profileForm.addEventListener("submit",async(event)=>{
  event.preventDefault();
  try{
    const res=await fetch(config.profilePath,{
      method:"PATCH",
      credentials:"same-origin",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({display_name:displayName.value,recovery_email:recoveryEmail.value})
    });
    if(!res.ok){throw new Error("Profile update failed");}
    profileStatus.textContent="Profile saved.";
    await loadProfile();
  }catch(err){profileStatus.textContent=err.message;}
});
inviteForm.addEventListener("submit",async(event)=>{
  event.preventDefault();
  const data=new FormData(inviteForm);
  try{
    const res=await fetch(config.usersPath,{
      method:"POST",
      credentials:"same-origin",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({email:data.get("email"),display_name:data.get("display_name"),role:data.get("role")})
    });
    if(!res.ok){throw new Error("Admin invite failed");}
    const payload=await res.json();
    inviteForm.reset();
    inviteStatus.textContent=payload.setup_url||payload.code||"Admin added.";
    await loadUsers();
  }catch(err){inviteStatus.textContent=err.message;}
});
addPasskey.addEventListener("click",async()=>{
  try{
    if(!window.PublicKeyCredential){throw new Error("This browser does not support passkeys.");}
    const begin=await fetch(config.passkeyBeginPath,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({label:"Passkey"})});
    if(!begin.ok){throw new Error("Passkey setup unavailable");}
    const payload=await begin.json();
    const credential=await navigator.credentials.create(webauthnCreationOptions(payload.options));
    const finish=await fetch(config.passkeyFinishPath,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({label:"Passkey",session_data:payload.session_data,credential:JSON.stringify(creationResponsePayload(credential))})});
    if(!finish.ok){throw new Error("Passkey registration failed");}
    credentialsEl.textContent="Passkey added.";
    await loadCredentials();
  }catch(err){credentialsEl.textContent=err.message;}
});
beginTotp.addEventListener("click",async()=>{
  beginTotp.disabled=true;
  try{
    const begin=await fetch(config.totpBeginPath,{method:"POST",credentials:"same-origin"});
    if(!begin.ok){throw new Error("2FA setup unavailable");}
    const setup=await begin.json();
    const secret=setup.secret||"";
    if(!secret){throw new Error("2FA secret unavailable");}
    const provisioningUri=setup.provisioning_uri||"";
    credentialsEl.textContent=provisioningUri?"Use authenticator URI: "+provisioningUri:"Authenticator secret generated";
    const code=window.prompt("Enter the 6-digit code from your authenticator app");
    if(!code){setTotpEnrollmentState(false);return;}
    const verify=await fetch(config.totpVerifyPath,{
      method:"POST",
      credentials:"same-origin",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({secret:secret,code:code,label:"Authenticator app"})
    });
    if(!verify.ok){throw new Error("2FA verification failed");}
    await loadCredentials();
  }catch(err){
    credentialsEl.textContent=err.message;
    setTotpEnrollmentState(false);
  }
});
loadProfile().catch(err=>{profileEl.textContent=err.message;});
loadCredentials().catch(err=>{credentialsEl.textContent=err.message;});
loadUsers().catch(err=>{usersEl.textContent=err.message;});
  </script>
</body>
</html>`
