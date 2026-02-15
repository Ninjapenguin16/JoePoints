const BASE = "";

// DOM elements — use IDs from the markup
const apiKeyInput = document.getElementById("apiKey");
const uidInput = document.getElementById("uidField");
const removeUidInput = document.getElementById("removeUid");
const firstInput = document.getElementById("first");
const lastInput = document.getElementById("last");
const lookupFirstInput = document.getElementById("lookupFirst");
const lookupLastInput = document.getElementById("lookupLast");
const pointsInput = document.getElementById("points");

const output = document.getElementById("output");
const usersTableBody = document.querySelector("#userTable tbody");

let apiKey = "";
let lastRawResponse = null;

/* =========================
   Helpers
========================= */

function truncate(text, max = 20) {
  const str = String(text || '');
  return str.length > max ? str.substring(0, max) + '...' : str;
}

function authHeaders(isPost=false){
  const h = { "Accept":"application/json" };
  if(isPost) h["Content-Type"] = "application/json";
  if(apiKey) h["Authorization"] = `Bearer ${apiKey}`;
  return h;
}

async function fetchJSON(path, options={}){
  const res = await fetch(BASE + path, options);
  const text = await res.text();
  lastRawResponse = text;
  let data;

  try { data = JSON.parse(text); }
  catch { data = { raw:text }; }

  if(!res.ok) throw data;
  return data;
}

/* =========================
   Pretty Output
========================= */

function clearOutput(){ output.innerHTML = ""; }

function addCard(type, title, content){
  const card = document.createElement("div");
  card.className = "card " + type;
  const h = document.createElement("div");
  h.className = "card-title"; h.textContent = title;
  const c = document.createElement("div"); c.className = "card-content";
  const pre = document.createElement('pre');
  if(typeof content === "object") pre.textContent = JSON.stringify(content,null,2);
  else pre.textContent = String(content);
  c.appendChild(pre);
  card.appendChild(h); card.appendChild(c);
  output.prepend(card);
}

function showSuccess(title, msg){ addCard("success", "✔ " + title, msg); }
function showError(err){ const msg = err?.error || err?.raw || JSON.stringify(err); addCard("error", "✖ Error", msg); printOutput(); }
function showInfo(title, msg){ addCard("info", title, msg); }

// Print exact server response (safe) into the bottom pre.
function printOutput(){
  if(lastRawResponse !== null){
    output.textContent = lastRawResponse;
  } else {
    output.textContent = "";
  }
}

/* =========================
   Users table
========================= */

// XHR GET-with-body helper removed for production; server should accept POST RPC calls.

async function refreshUsers(){
  try{
    const users = await fetchJSON("/api/getall", { method: 'POST', headers: authHeaders(true), body: JSON.stringify({}) });

    if(!usersTableBody) return;
    usersTableBody.innerHTML = "";

    users.forEach(u=>{
      const tr = document.createElement("tr");
      const tdUid = document.createElement('td'); tdUid.textContent = String(u.uid);
      const tdFirst = document.createElement('td'); tdFirst.textContent = truncate(u.first);
      const tdLast = document.createElement('td'); tdLast.textContent = truncate(u.last);
      const tdPoints = document.createElement('td'); tdPoints.textContent = String(u.points);
      tdUid.className = tdFirst.className = tdLast.className = tdPoints.className = 'p-2';
      tr.appendChild(tdUid); tr.appendChild(tdFirst); tr.appendChild(tdLast); tr.appendChild(tdPoints);
      usersTableBody.appendChild(tr);
    });

  }catch(e){ showError(e); }
}

/* =========================
   Actions
========================= */

async function addUser(){
  try{
    const data = await fetchJSON("/api/addperson",{
      method:"POST",
      headers:authHeaders(true),
      body:JSON.stringify({ first:firstInput.value, last:lastInput.value })
    });

    if(data.uid && uidInput) uidInput.value = data.uid;
    if(data.uid && removeUidInput) removeUidInput.value = data.uid;
    showSuccess("User Added", data);
    // print exact server JSON
    printOutput();
    firstInput.value = '';
    lastInput.value = '';
    refreshUsers();

  }catch(e){ showError(e); }
}

// The markup calls some different function names — provide small wrappers
function addPerson(){ return addUser(); }
function getAll(){ return refreshUsers(); }

// getUID: server expects a JSON body on GET (see api.go). We send a GET with a JSON body and Content-Type.
async function getUID(){
  try{
    const data = await fetchJSON('/api/getuid', { method: 'POST', headers: authHeaders(true), body: JSON.stringify({ first: lookupFirstInput.value, last: lookupLastInput.value }) });

    // server returns an array of uids; pick first if available
    if(uidInput){
      if(Array.isArray(data) && data.length) uidInput.value = data[0].uid ?? data[0];
      else if(data.uid !== undefined) uidInput.value = data.uid;
    }
    // Autofill removeUid input from uidField
    if(uidInput && uidInput.value){
      removeUidInput.value = uidInput.value;
    }
    showInfo("UID Found", data);
    printOutput();
  }catch(e){ showError(e); }
}

// getPoints: mirror server expectation (GET with JSON body)
async function getPoints(){
  try{
    const data = await fetchJSON('/api/getpoints', { method: 'POST', headers: authHeaders(true), body: JSON.stringify({ uid: Number(uidInput?.value) }) });
    // Autofill points input when server returns {"points": N}
    if(data && typeof data === 'object' && data.points !== undefined){
      pointsInput.value = String(data.points);
    }
    showInfo("Points", data);
    printOutput();
  }catch(e){ showError(e); }
}

async function setPoints(){
  try{
    const data = await fetchJSON("/api/setpoints",{
      method:"POST",
      headers:authHeaders(true),
      body:JSON.stringify({ uid:Number(uidInput.value), points:Number(pointsInput.value) })
    });

    showSuccess("Points Set", data);
    printOutput();
    refreshUsers();
  }catch(e){ showError(e); }
}

async function addPoints(){
  try{
    const data = await fetchJSON("/api/addpoints",{
      method:"POST",
      headers:authHeaders(true),
      body:JSON.stringify({ uid:Number(uidInput.value), points:Number(pointsInput.value) })
    });

    showSuccess("Points Added", data);
    printOutput();
    refreshUsers();
  }catch(e){ showError(e); }
}

// removePerson: called by markup
async function removePerson(){
  try{
    const data = await fetchJSON("/api/removeperson",{
      method:"POST",
      headers:authHeaders(true),
      body:JSON.stringify({ uid:Number(removeUidInput.value) })
    });

    showSuccess("User Removed", data);
    printOutput();
    removeUidInput.value = '';
    refreshUsers();
  }catch(e){ showError(e); }
}

/* =========================
   Key / Modal handling
========================= */

function openGenKeyModal(){ document.getElementById('genKeyModal')?.classList.remove('hidden'); }
function closeGenKeyModal(){ document.getElementById('genKeyModal')?.classList.add('hidden'); }
function confirmRevokeKey(){ document.getElementById('revokeModal')?.classList.remove('hidden'); }
function closeRevokeModal(){ document.getElementById('revokeModal')?.classList.add('hidden'); }

async function genKey(){
  try{
    const identifier = document.getElementById('identifierInput')?.value || '';
    const data = await fetchJSON('/api/genkey',{
      method: 'POST',
      headers: authHeaders(true),
      body: JSON.stringify({ identifier })
    });

    showSuccess('Key Generated', data);
    printOutput();
    closeGenKeyModal();
  }catch(e){ showError(e); }
}

async function removeKey(){
  try{
    const data = await fetchJSON('/api/removekey',{
      method: 'POST',
      headers: authHeaders(true),
      body: JSON.stringify({})
    });

    showSuccess('Key Revoked', data);
    printOutput();
    closeRevokeModal();
  }catch(e){ showError(e); }
}

async function getIdentifier(){
  try{
    const data = await fetchJSON('/api/getidentifier',{
      method: 'POST',
      headers: authHeaders(true),
      body: JSON.stringify({})
    });
    printOutput();
  }catch(e){ showError(e); }
}

/* =========================
   Key input wiring
========================= */

if(apiKeyInput) apiKeyInput.addEventListener("input", ()=>{ apiKey = apiKeyInput.value.trim(); });

/* =========================
   AUTO LOAD USERS ON OPEN ⭐
========================= */

document.addEventListener("DOMContentLoaded", ()=>{ refreshUsers(); });
