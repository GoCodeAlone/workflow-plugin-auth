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
    </section>
    <section>
      <h2>Sign-in & 2FA</h2>
      <p id="credentials" class="muted">Loading credentials...</p>
      <button id="beginTotp" type="button">Set up 2FA</button>
    </section>
    <section>
      <h2>Users</h2>
      <p id="users" class="muted">Loading users...</p>
    </section>
  </main>
  <script>window.__WORKFLOW_AUTH_IDENTITY_UI__=%s;</script>
  <script>
const config=window.__WORKFLOW_AUTH_IDENTITY_UI__;
const profileEl=document.getElementById("profile");
const credentialsEl=document.getElementById("credentials");
const usersEl=document.getElementById("users");
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
  profileEl.textContent=[user.display_name,user.email].filter(Boolean).join(" · ")||"Profile loaded";
}
async function loadCredentials(){
  const res=await fetch(config.credentialsPath,{credentials:"same-origin"});
  if(!res.ok){throw new Error("Credentials unavailable");}
  const payload=await res.json();
  setTotpEnrollmentState(Boolean(payload.totp_enrolled));
  credentialsEl.textContent=(payload.count||0)+" credential(s)";
}
async function loadUsers(){
  const res=await fetch(config.usersPath,{credentials:"same-origin"});
  if(!res.ok){usersEl.textContent="Users unavailable";return;}
  const payload=await res.json();
  usersEl.textContent=((payload.users||[]).length)+" user(s)";
}
Promise.all([loadProfile(),loadCredentials(),loadUsers()]).catch(err=>{
  profileEl.textContent=err.message;
});
  </script>
</body>
</html>`
