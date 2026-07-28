const modules=[['dashboard','Dashboard','Pregled mrežne infrastrukture'],['interfaces','Interfaces','Mrežni NIC-evi — status i identifikacija porta'],['dns','DNS','PowerDNS zone i zapisi'],['dhcp','DHCP','Kea subneti, rezervacije i leaseovi'],['gateway','Gateway','WAN/LAN, NAT i port forwarding'],['routing','Routing','Statičke rute — mreža do gatewaya/interfacea'],['aliasi','Aliasi','Imenovani objekti (host/mreža/raspon) — koristi ih firewall i VPN'],['fwrules','Firewall pravila','Aliasi (host/mreža) i custom pravila'],['ids','IDS/IPS','Suricata detekcija i prevencija upada'],['rpz','DNS filtering','RPZ blokiranje domena (radi i na slabom hardveru)'],['webproxy','Web proxy','Squid cache + e2guardian filtriranje URL-ova'],['vpn','VPN','WireGuard pristup na daljinu'],['openvpn','OpenVPN','OpenVPN pristup na daljinu (cert + split-tunnel)'],['sitevpn','Site-to-Site','WireGuard net-to-net tuneli između lokacija'],['ipsec','IPsec IKEv2','Site-to-site s trećim uređajima (Fortinet, MikroTik, Cisco…)'],['certificates','Certificates','Step CA i javni ACME certifikati'],['proxy','Reverse Proxy','Nginx aplikacije i TLS'],['monitoring','Monitoring','Zdravlje servisa i upozorenja'],['services','Servisi','Start / stop / restart servisa za troubleshooting'],['conflicts','Konflikti','Preklapanja subneta/poolova i duplikati'],['tools','Alati','Mrežni alati: ping, nslookup, traceroute, mtr'],['diagnostics','Dijagnostika','Zašto paket pada — odbačeni promet, razlog i pravilo koje ga hvata'],['backup','Backup','Sigurne kopije, cilj i restore drill'],['multiwan','Multi-WAN','Više WAN veza, težine i failover'],['system','Sustav','Način rada: Gateway/UTM ili lokalni router'],['configver','Verzije konfiguracije','Snimke konfiguracije — pregled promjena i vraćanje na prethodno stanje'],['packages','Ažuriranja','Verzije servisa i sigurnosna ažuriranja'],['mail','Mail','SMTP alarmi i agregacija događaja'],['siem','SIEM / Logovi','Prosljeđivanje događaja na vanjski SIEM (syslog/CEF)'],['users','Users','Korisnici, MFA i ovlasti'],['audit','Audit log','Evidencija administratorskih promjena']];
const $=s=>document.querySelector(s); let current='dashboard'; let dashTimer=null; let lastMetric=null; let dashTick=0;
function csrfToken(){const m=document.cookie.match(/(?:^|;\s*)saguaro_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):''}
async function api(path,options={}){const headers={'Content-Type':'application/json'};const method=(options.method||'GET').toUpperCase();if(method!=='GET'&&method!=='HEAD'){headers['X-CSRF-Token']=csrfToken()}const r=await fetch(path,{...options,headers:{...headers,...(options.headers||{})}});if(r.status===401){showLogin();throw Error('Prijava je istekla.')}const body=await r.json();if(!r.ok)throw Error(body.error||'Greška zahtjeva');return body}
function showLogin(){$('#login').classList.remove('hidden');$('#shell').classList.add('hidden')}
let sysProfile={profile:'gateway',gateway:true,utm:true};
let meRole='';
let nicLabels={};
function nlabel(n){return nicLabels[n]?nicLabels[n]+' ('+n+')':n}
async function loadNicLabels(){try{const ni=await api('/api/interfaces');nicLabels={};ni.forEach(n=>{if(n.label)nicLabels[n.name]=n.label})}catch(e){}}
async function showShell(){$('#login').classList.add('hidden');$('#shell').classList.remove('hidden');try{sysProfile=await api('/api/system')}catch(e){}try{meRole=(await api('/api/profile')).role||''}catch(e){}
// Reboot/poweroff are admin-only; reveal them only for admins.
if(meRole==='admin'){$('#mReboot').classList.remove('hidden');$('#mPoweroff').classList.remove('hidden')}else{$('#mReboot').classList.add('hidden');$('#mPoweroff').classList.add('hidden')}
await loadNicLabels();wireNavSearch();renderNav();const _h=(location.hash||'').replace(/^#/,'');if(_h&&modules.some(m=>m[0]===_h))current=_h;openModule(current);window.addEventListener('hashchange',()=>{const id=(location.hash||'').replace(/^#/,'');if(id&&id!==current&&modules.some(m=>m[0]===id))openModule(id)})}
async function devPower(action){const label=action==='reboot'?'restartati':'isključiti';if(!confirm(`Sigurno želiš ${label} uređaj? Veza s GUI-jem će se prekinuti.`))return;$('#devMenu').classList.add('hidden');try{const r=await api(`/api/system/power/${action}`,{method:'POST',body:'{}'});alert(r.message||'OK')}catch(e){alert(e.message)}}
function help(html){return `<details class="help"><summary>Kako ovo postaviti?</summary><div>${html}</div></details>`}
const svg=p=>`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const ICONS={
  dashboard:svg('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>'),
  interfaces:svg('<rect x="3" y="9" width="18" height="10" rx="2"/><path d="M7 9V6h10v3M8 19v2M16 19v2M12 19v2"/>'),
  dns:svg('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>'),
  dhcp:svg('<rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 14V9a5 5 0 0 1 10 0v5M12 4v3"/><circle cx="7.5" cy="17" r=".6" fill="currentColor"/>'),
  gateway:svg('<rect x="2" y="13" width="20" height="7" rx="2"/><path d="M8 13V8l-2 2m2-2 2 2M16 13V8l-2 2m2-2 2 2"/>'),
  ids:svg('<path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z"/><path d="M9.5 12l1.8 1.8L15 10"/>'),
  rpz:svg('<path d="M3 5h18l-7 8v6l-4 2v-8z"/>'),
  certificates:svg('<circle cx="12" cy="9" r="6"/><path d="M9 14l-2 7 5-3 5 3-2-7"/>'),
  proxy:svg('<path d="M4 8h13l-3-3m3 3-3 3M20 16H7l3-3m-3 3 3 3"/>'),
  monitoring:svg('<path d="M3 12h4l2-6 4 12 2-6h6"/>'),
  backup:svg('<rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v11a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8M10 12h4"/>'),
  multiwan:svg('<circle cx="12" cy="19" r="2"/><path d="M12 17V9M12 9 6 5M12 9l6-4"/><circle cx="6" cy="4" r="1.6"/><circle cx="18" cy="4" r="1.6"/>'),
  routing:svg('<path d="M4 7h9a4 4 0 0 1 4 4v6"/><path d="m14 4 3 3-3 3"/><path d="m10 20-3-3 3-3"/><path d="M20 17h-9"/>'),
  sitevpn:svg('<rect x="2" y="8" width="7" height="8" rx="1.5"/><rect x="15" y="8" width="7" height="8" rx="1.5"/><path d="M9 12h6"/><path d="M12 10.5v3"/>'),
  ipsec:svg('<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1.4"/>'),
  services:svg('<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>'),
  fwrules:svg('<path d="M12 3 4 6v5c0 4 3.4 7.4 8 9 4.6-1.6 8-5 8-9V6z"/><path d="M9 12h6"/>'),
  conflicts:svg('<path d="M10.3 4 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 4a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>'),
  siem:svg('<path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1.6"/>'),
  tools:svg('<path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L4 16.8V20h3.2l5.3-5.3a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.1-.5-.5-2.1z"/>'),
  webproxy:svg('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>'),
  system:svg('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 7 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0-1.1-2.7H1a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 2.6 7"/>'),
  mail:svg('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>'),
  vpn:svg('<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.3"/>'),
  openvpn:svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v10M9 9l3-2 3 2M9 15l3 2 3-2"/>'),
  users:svg('<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3 3-5 6-5s6 2 6 5"/><path d="M16 6a3 3 0 0 1 0 6M21 20c0-2.5-1.8-4.2-4-4.7"/>'),
  audit:svg('<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h4"/>'),
  aliasi:svg('<path d="M7 7h6a4 4 0 0 1 0 8H9"/><path d="M17 17H11a4 4 0 0 1 0-8h2"/>'),
  _default:svg('<circle cx="12" cy="12" r="9"/>')
};
// Small action icons for per-row buttons.
const AICON={
  up:svg('<path d="m6 15 6-6 6 6"/>'),
  down:svg('<path d="m6 9 6 6 6-6"/>'),
  edit:svg('<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>'),
  del:svg('<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>'),
  play:svg('<path d="m7 4 13 8-13 8z"/>'),
  stop:svg('<rect x="6" y="6" width="12" height="12" rx="1.5"/>'),
  restart:svg('<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/>'),
  test:svg('<path d="M9 3h6M10 3v6L5 19a1.5 1.5 0 0 0 1.4 2h11.2A1.5 1.5 0 0 0 19 19l-5-10V3"/>')
};
// iconBtn renders a titled square icon button; cls adds e.g. "danger", attrs carries data-*.
function iconBtn(icon,title,cls,attrs){return `<button type="button" class="iconbtn${cls?' '+cls:''}" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}"${attrs?' '+attrs:''}>${AICON[icon]||''}</button>`}
// drawerStyle is the shared inline style for a hidden add/edit form panel (the
// "list-first" pattern: the form is a drawer that opens on +Dodaj / Uredi and
// hides on Spremi/Odustani, instead of sitting open under the list).
const drawerStyle="display:none;border:1px solid var(--line,#394150);border-radius:8px;padding:.7rem .9rem;margin:.5rem 0";
// makeDrawer wires that panel: it handles show/hide, the title text, and the
// "+ Dodaj" / "Odustani" buttons. The caller supplies reset() (clear the form to
// add-defaults) and, when editing a row, prefills the fields then calls edit(title).
// All ids are element ids WITHOUT the leading '#'. Returns {add, edit, close}.
function makeDrawer({form,title,newBtn,cancel,addTitle,reset,focus}){
  const f=document.getElementById(form),t=title&&document.getElementById(title);
  const foc=()=>{if(focus){const x=document.getElementById(focus);if(x)x.focus()}};
  const open=txt=>{f.style.display='';if(t)t.textContent=txt;foc();f.scrollIntoView({block:'nearest'})};
  const close=()=>{f.style.display='none';if(reset)reset();if(t)t.textContent=addTitle||''};
  const add=()=>{if(reset)reset();open(addTitle||'')};
  if(newBtn){const b=document.getElementById(newBtn);if(b)b.onclick=add}
  if(cancel){const c=document.getElementById(cancel);if(c)c.onclick=close}
  return {add,edit:open,close};
}
// tableSearch wires a search box to filter a <tbody>'s rows by their visible text
// (client-side, case-insensitive). For lists that can outgrow the screen.
function tableSearch(inputId,tbodyId){const inp=document.getElementById(inputId),tb=document.getElementById(tbodyId);if(!inp||!tb)return;
  inp.oninput=()=>{const q=inp.value.toLowerCase().trim();let shown=0,total=0;tb.querySelectorAll('tr').forEach(tr=>{if(tr.querySelector('td[colspan]'))return;total++;const ok=!q||tr.textContent.toLowerCase().includes(q);tr.style.display=ok?'':'none';if(ok)shown++});const c=document.getElementById(inputId+'Cnt');if(c)c.textContent=q?`${shown}/${total}`:''}}
// searchBar returns a small search input (+ live count) for placing above a table.
function searchBar(inputId,placeholder){return `<div class="filterbar"><input id="${inputId}" type="search" placeholder="${escapeHtml(placeholder)}" autocomplete="off" style="max-width:280px"><span id="${inputId}Cnt" class="muted small" style="align-self:center"></span></div>`}
// tabBar + wireTabs drive in-module tabs; panes are <div class="tabpane" data-pane="ID" data-tabkey="KEY">.
function tabBar(id,tabs){return `<div class="tabs" id="${id}">${tabs.map((t,i)=>`<button type="button" class="tab${i===0?' active':''}" data-tab="${escapeHtml(t[0])}">${escapeHtml(t[1])}${t[2]!=null?`<span class="badge">${t[2]}</span>`:''}</button>`).join('')}</div>`}
function wireTabs(id){const bar=document.getElementById(id);if(!bar)return;bar.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{bar.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll(`[data-pane="${id}"]`).forEach(p=>p.classList.toggle('active',p.dataset.tabkey===b.dataset.tab))})}
// toggle renders a sliding on/off switch wrapping a real checkbox (id preserved so existing reads work).
function toggle(id,checked,label,extra){return `<label class="toggle-row"><span class="toggle"><input type="checkbox" id="${id}" ${checked?'checked':''}${extra||''}><span class="track"></span></span><span>${label}</span></label>`}
const UTM_MODULES=new Set(['gateway','aliasi','fwrules','ids','webproxy','vpn','openvpn','sitevpn','ipsec','multiwan']);
// Each group is [title, iconKey, [moduleIds]]. The left rail shows only these
// groups; the modules of the active group appear as tabs across the top of the
// content as tabs, so the rail stays short no matter how many modules.
const NAV_GROUPS=[
 ['Status','monitoring',['dashboard','monitoring','diagnostics','conflicts','tools','audit']],
 ['Mreža','interfaces',['interfaces','gateway','routing','aliasi','multiwan']],
 ['DNS i DHCP','dns',['dns','dhcp','rpz']],
 ['Vatrozid','fwrules',['fwrules','ids','webproxy']],
 ['VPN','vpn',['vpn','openvpn','sitevpn','ipsec']],
 ['Servisi i TLS','services',['certificates','proxy','services','backup','mail','siem']],
 ['Sustav','system',['system','configver','packages','users']],
];
const byId=Object.fromEntries(modules.map(m=>[m[0],m]));
let currentGroup=0; const lastByGroup={};
// A module is hidden when it is UTM-only and the box is not in gateway mode.
function modHidden(id){return !sysProfile.gateway&&UTM_MODULES.has(id)}
function groupVisibleIds(gi){const g=NAV_GROUPS[gi];return g?g[2].filter(id=>byId[id]&&!modHidden(id)):[]}
function groupIndexOf(id){return NAV_GROUPS.findIndex(g=>g[2].includes(id))}
// renderNav draws the left rail: one button per group. The active group (the
// one holding the current module) is highlighted. Sub-navigation (the modules
// themselves) is rendered by renderSubnav, which this always keeps in sync.
function renderNav(){const nav=$('#nav');nav.innerHTML='';
for(let gi=0;gi<NAV_GROUPS.length;gi++){if(!groupVisibleIds(gi).length)continue;
const g=NAV_GROUPS[gi];const b=document.createElement('button');
b.className='nav-cat'+(gi===currentGroup?' active':'');
b.innerHTML=`<span class="nav-ico">${ICONS[g[1]]||ICONS._default}</span><span>${escapeHtml(g[0])}</span>`;
b.onclick=()=>selectGroup(gi);nav.appendChild(b)}
renderSubnav()}
// selectGroup switches the rail to a group and opens its last-visited module
// (or the first one), so returning to a group lands where you left off.
function selectGroup(gi){const vis=groupVisibleIds(gi);if(!vis.length)return;currentGroup=gi;
const target=lastByGroup[gi]&&vis.includes(lastByGroup[gi])?lastByGroup[gi]:vis[0];openModule(target)}
// renderSubnav draws the top tab strip for the active group's modules.
function renderSubnav(){const sub=$('#subnav');if(!sub)return;const vis=groupVisibleIds(currentGroup);
if(vis.length<=1){sub.innerHTML='';sub.classList.add('hidden');return}
sub.classList.remove('hidden');
sub.innerHTML=vis.map(id=>`<button type="button" class="subtab${id===current?' active':''}" data-id="${id}"><span class="subtab-ico">${ICONS[id]||ICONS._default}</span><span>${escapeHtml(byId[id][1])}</span></button>`).join('');
sub.querySelectorAll('.subtab').forEach(b=>b.onclick=()=>openModule(b.dataset.id))}
// wireNavSearch powers the rail search box: type to filter every module by name
// and jump straight to it, regardless of which group it lives in.
function wireNavSearch(){const inp=$('#navSearch'),res=$('#navResults');if(!inp||!res)return;
const hide=()=>{res.classList.add('hidden');res.innerHTML=''};
const run=()=>{const q=inp.value.trim().toLowerCase();if(!q){hide();return}
const hits=modules.filter(m=>!modHidden(m[0])&&(m[1].toLowerCase().includes(q)||m[0].includes(q))).slice(0,8);
if(!hits.length){res.innerHTML='<div class="navres-empty">Nema rezultata</div>';res.classList.remove('hidden');return}
res.innerHTML=hits.map(m=>`<button type="button" class="navres" data-id="${m[0]}"><span class="nav-ico">${ICONS[m[0]]||ICONS._default}</span><span>${escapeHtml(m[1])}</span></button>`).join('');
res.classList.remove('hidden');
res.querySelectorAll('.navres').forEach(b=>b.onclick=()=>{inp.value='';hide();openModule(b.dataset.id)})};
inp.oninput=run;
inp.onkeydown=e=>{if(e.key==='Escape'){inp.value='';hide()}else if(e.key==='Enter'){const first=res.querySelector('.navres');if(first){inp.value='';hide();openModule(first.dataset.id)}}};
inp.onblur=()=>setTimeout(hide,150)}
function stClass(s){return({healthy:'st-healthy',error:'st-error',unknown:'st-unknown','not-configured':'st-muted'})[s]||''}
async function openModule(id){if(dashTimer){clearInterval(dashTimer);dashTimer=null}current=id;
if((location.hash||'').replace(/^#/,'')!==id){try{history.replaceState(null,'','#'+id)}catch(e){}}
const gi=groupIndexOf(id);if(gi>=0){currentGroup=gi;lastByGroup[gi]=id}
renderNav();const m=modules.find(x=>x[0]===id);$('#title').textContent=m[1];$('#description').textContent=m[2];$('#content').innerHTML='<div class="panel muted">Učitavanje…</div>';try{id==='dashboard'?await dashboard():id==='interfaces'?await interfacesPage():id==='audit'?await audit():id==='monitoring'?await monitoring():id==='mail'?await mailPage():id==='dns'?await dnsPage():id==='dhcp'?await dhcpPage():id==='users'?await usersPage():id==='gateway'?await gatewayPage():id==='routing'?await routingPage():id==='aliasi'?await aliasesPage():id==='fwrules'?await fwRulesPage():id==='webproxy'?await webproxyPage():id==='ids'?await idsPage():id==='rpz'?await rpzPage():id==='proxy'?await proxyPage():id==='certificates'?await certsPage():id==='vpn'?await vpnPage():id==='openvpn'?await openvpnPage():id==='backup'?await backupPage():id==='multiwan'?await multiwanPage():id==='siem'?await siemPage():id==='sitevpn'?await s2sPage():id==='ipsec'?await ipsecPage():id==='system'?await systemPage():id==='configver'?await configVersionsPage():id==='services'?await servicesCtlPage():id==='packages'?await packagesPage():id==='conflicts'?await conflictsPage():id==='diagnostics'?await diagPage():id==='tools'?await toolsPage():($('#content').innerHTML=`<div class="panel muted">Nepoznat modul: ${escapeHtml(id)}</div>`)}catch(e){$('#content').innerHTML=`<div class="panel error">${escapeHtml(e.message)}</div>`}}
function fmtRate(bps){if(!isFinite(bps)||bps<0)bps=0;if(bps>=1e9)return (bps/1e9).toFixed(2)+' Gb/s';if(bps>=1e6)return (bps/1e6).toFixed(1)+' Mb/s';if(bps>=1e3)return (bps/1e3).toFixed(0)+' kb/s';return Math.round(bps)+' b/s'}
function fmtUptime(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+'d ':'')+h+'h '+m+'m'}
function fmtBytes(n){n=+n||0;if(n>=1e9)return (n/1e9).toFixed(2)+' GB';if(n>=1e6)return (n/1e6).toFixed(1)+' MB';if(n>=1e3)return (n/1e3).toFixed(0)+' kB';return n+' B'}
function barPct(p){const cl=p>=85?'var(--err)':p>=60?'var(--warn)':'var(--brand)';return `<div class="bar"><i style="width:${Math.min(100,Math.max(0,p))}%;background:${cl}"></i></div>`}
// loadSecurity fills the dashboard "Sigurnost" view: firewall drop counters,
// recent security-severity events, and the IDS/IPS alert count.
async function loadSecurity(){
try{const fc=await api('/api/firewall/counters');const d=fc.drops||{};const f=d.forward,i=d.input;
if($('#secFwd')){$('#secFwd').textContent=f?(+f.packets).toLocaleString('hr-HR'):'0';if($('#secFwdB'))$('#secFwdB').textContent=f?fmtBytes(f.bytes):''}
if($('#secIn')){$('#secIn').textContent=i?(+i.packets).toLocaleString('hr-HR'):'0';if($('#secInB'))$('#secInB').textContent=i?fmtBytes(i.bytes):''}}catch(e){}
try{const rows=await api('/api/events?limit=100');const sev=new Set(['security','critical','error','warning']);const sec=(rows||[]).filter(x=>sev.has((x.severity||'').toLowerCase()));
if($('#secEvN'))$('#secEvN').textContent=sec.length;const el=$('#secEvents');
if(el){el.innerHTML=sec.length?`<table class="compact"><thead><tr><th>Vrijeme</th><th>Razina</th><th>Modul</th><th>Izvor</th><th>Poruka</th><th></th></tr></thead><tbody>${sec.slice(0,50).map(x=>`<tr><td class="muted">${new Date(x.ts).toLocaleString()}</td><td class="sev-${escapeHtml(x.severity||'info')}">${escapeHtml(x.severity)}</td><td>${escapeHtml(x.module)}</td><td class="muted">${escapeHtml(x.srcIp||'—')}</td><td>${escapeHtml(x.message||x.action||'')}</td><td class="rowacts">${x.srcIp?`<button class="secBlk danger" data-ip="${escapeHtml(x.srcIp)}">Blokiraj</button>`:''}</td></tr>`).join('')}</tbody></table>`:'<span class="muted">Nema nedavnih sigurnosnih događaja.</span>';
el.querySelectorAll('.secBlk').forEach(b=>b.onclick=async()=>{if(!confirm('Blokirati sav proslijeđeni promet s '+b.dataset.ip+'?'))return;b.disabled=true;b.textContent='Blokiram…';try{await api('/api/firewall/block-ip',{method:'POST',body:JSON.stringify({ip:b.dataset.ip})});b.textContent='Blokiran';}catch(err){b.disabled=false;b.textContent='Blokiraj';alert(err.message)}})}}catch(e){}
try{const s=await api('/api/logs/suricata');if($('#secAlerts'))$('#secAlerts').textContent=(s.alerts||[]).length}catch(e){}
try{const h=await api('/api/rpz/hits');const top=h.top||[];const el=$('#secRpz');if(el){const max=top.reduce((m,x)=>Math.max(m,x.count),0)||1;el.innerHTML=top.length?`<table class="compact"><tbody>${top.map(x=>`<tr><td style="width:45%"><b>${escapeHtml(x.domain)}</b></td><td><div class="bar" style="margin:0"><i style="width:${Math.round(100*x.count/max)}%;background:var(--err)"></i></div></td><td style="width:60px;text-align:right" class="muted">${x.count}</td></tr>`).join('')}</tbody></table>`:'<span class="muted">Nema blokiranih domena (uključi DNS filtering / RPZ).</span>';}}catch(e){}}
async function dashboard(){const services=await api('/api/services').catch(()=>[]);const nics=await api('/api/interfaces').catch(()=>[]);const eh=escapeHtml;
const nicHw=nics.map(n=>`<tr><td><b>${eh(n.label||n.name)}</b> <span class="muted small">${eh(n.name)}</span></td><td>${n.role?`<span class="badge">${eh(n.role)}</span>`:'<span class="muted">—</span>'}</td><td>${n.carrier?`<span class="status st-healthy">Spojen${n.speedMb?' · '+n.speedMb+' Mbps':''}</span>`:'<span class="status st-muted">Nije spojen</span>'}</td><td class="muted">${eh((n.addresses||[]).join(', ')||'—')}</td><td class="muted small">${eh(n.sysName||'')}${n.driver?' · '+eh(n.driver):''}</td></tr>`).join('')||'<tr><td colspan="5" class="muted">Nema podataka.</td></tr>';
$('#content').innerHTML=`${tabBar('dashViews',[['hw','Stanje i hardver'],['std','Standard'],['sec','Sigurnost']])}
<div class="tabpane active" data-pane="dashViews" data-tabkey="hw">
<div class="cards">
<div class="card"><div class="muted">CPU</div><div class="metric" id="mCpu">—</div><div id="mCpuBar"></div><div class="muted" id="mLoad" style="font-size:12px;margin-top:6px"></div></div>
<div class="card"><div class="muted">Memorija</div><div class="metric" id="mMem">—</div><div id="mMemBar"></div><div class="muted" id="mMemSub" style="font-size:12px;margin-top:6px"></div></div>
<div class="card"><div class="muted">Conntrack sesije</div><div class="metric" id="mCt">—</div><div id="mCtBar"></div><div class="muted" id="mCtSub" style="font-size:12px;margin-top:6px"></div></div>
<div class="card"><div class="muted">Uptime</div><div class="metric" id="mUp" style="font-size:22px">—</div><div class="muted" id="mSvc" style="font-size:12px;margin-top:10px"></div></div></div>
<div class="panel"><h2>CPU po jezgrama</h2><div id="mCores" class="cores"></div></div>
<div class="panel"><h2>Mrežni portovi (hardver)</h2><table class="compact"><thead><tr><th>Port</th><th>Uloga</th><th>Status / brzina</th><th>IP</th><th>Hardver</th></tr></thead><tbody>${nicHw}</tbody></table></div></div>
<div class="tabpane" data-pane="dashViews" data-tabkey="std">
<div class="panel"><h2>Mrežni promet (uživo)</h2><table class="compact"><thead><tr><th>Sučelje</th><th>Uloga</th><th>Link</th><th>↓ Prijem</th><th>↑ Slanje</th></tr></thead><tbody id="mIf"></tbody></table></div>
<div class="panel"><h2>DNS resolver (Unbound)</h2><div id="dnsStat" class="muted">Učitavanje…</div></div>
<div class="panel"><h2>Komponente</h2><div class="services">${services.map(s=>`<div class="card service"><div><h3>${escapeHtml(s.name)}</h3><p>${escapeHtml(s.description)}</p></div><div><span class="status ${stClass(s.status)}">${escapeHtml(s.status)}</span><button class="svcCheck" data-id="${escapeHtml(s.id)}">Provjeri</button></div></div>`).join('')}</div></div>
<div class="panel"><h2>Čarobnjaci</h2><div class="wizRow"><button id="wzNet">DHCP mreža (W2)</button> <button id="wzRes">DHCP rezervacija (W3)</button> <button id="wzZone">DNS zona (W4)</button> <button id="wzGw">Gateway (W8)</button> <button id="wzMail">Mail alarmi (W10)</button></div></div></div>
<div class="tabpane" data-pane="dashViews" data-tabkey="sec">
<div class="cards">
<div class="card"><div class="muted">Odbačeno — forward</div><div class="metric" id="secFwd" style="font-size:22px">—</div><div class="muted small" id="secFwdB"></div></div>
<div class="card"><div class="muted">Odbačeno — ulaz</div><div class="metric" id="secIn" style="font-size:22px">—</div><div class="muted small" id="secInB"></div></div>
<div class="card"><div class="muted">IDS/IPS alarmi</div><div class="metric" id="secAlerts" style="font-size:22px">—</div><div class="muted small">nedavni</div></div>
<div class="card"><div class="muted">Sigurnosni događaji</div><div class="metric" id="secEvN" style="font-size:22px">—</div><div class="muted small">nedavni</div></div></div>
<div class="panel"><h2>Top blokirane domene (RPZ)</h2><div id="secRpz" class="muted">Učitavanje…</div></div>
<div class="panel scroll"><h2>Sigurnosni događaji</h2><div id="secEvents" class="muted">Učitavanje…</div></div>
<div class="panel scroll"><h2>IDS/IPS alarmi (Suricata)</h2><div id="idsAlerts" class="muted">Učitavanje…</div></div></div>`;
wireTabs('dashViews');loadSecurity();
document.querySelectorAll('.svcCheck').forEach(b=>b.onclick=()=>checkService(b.dataset.id));
$('#wzNet').onclick=wizDhcpNet;$('#wzRes').onclick=wizReservation;$('#wzZone').onclick=wizDnsZone;$('#wzGw').onclick=()=>wizGateway().catch(e=>alert(e.message));$('#wzMail').onclick=()=>openModule('mail');
const healthy=services.filter(s=>s.status==='healthy').length;$('#mSvc').textContent=`${healthy}/${services.length} servisa zdravo`;
lastMetric=null;dashTick=0;await refreshMetrics();dashTimer=setInterval(refreshMetrics,2000)}
async function refreshLogs(){
try{const u=await api('/api/logs/unbound');const el=$('#dnsStat');if(!el)return;
el.innerHTML=u.available?`<div style="display:flex;gap:28px;flex-wrap:wrap">${[['Upiti',(u.queries||0).toLocaleString('hr-HR')],['Cache hit',(u.cacheHitPct||0)+'%'],['NXDOMAIN',(u.nxdomain||0).toLocaleString('hr-HR')],['SERVFAIL',(u.servfail||0).toLocaleString('hr-HR')]].map(([l,v])=>`<div><div class="muted" style="font-size:12px">${l}</div><div class="metric" style="font-size:22px">${v}</div></div>`).join('')}</div>`:'<span class="muted">Unbound statistika nedostupna (unbound-control nije konfiguriran).</span>';}catch(e){}
try{const s=await api('/api/logs/suricata');const el=$('#idsAlerts');if(!el)return;const a=s.alerts||[];
el.innerHTML=a.length?`<table class="compact"><thead><tr><th>Vrijeme</th><th>Sev</th><th>Signatura</th><th>Izvor → Odredište</th><th>Proto</th></tr></thead><tbody>${a.slice().reverse().map(x=>`<tr><td class="muted">${escapeHtml((x.time||'').replace('T',' ').slice(0,19))}</td><td class="sev-${x.severity<=1?'error':x.severity===2?'warning':'info'}">${x.severity}</td><td>${escapeHtml(x.signature||'')}</td><td class="muted">${escapeHtml(x.src||'')} → ${escapeHtml(x.dst||'')}</td><td class="muted">${escapeHtml(x.proto||'')}</td></tr>`).join('')}</tbody></table>`:'<span class="muted">Nema nedavnih IDS/IPS alarma (ili IDS nije uključen).</span>';}catch(e){}}
async function refreshMetrics(){let m;try{m=await api('/api/metrics')}catch(e){return}if(current!=='dashboard'||!$('#mCpu'))return;
const cpu=m.cpu||{};$('#mCpu').textContent=(cpu.avg||0).toFixed(0)+'%';$('#mCpuBar').innerHTML=barPct(cpu.avg||0);$('#mLoad').textContent=`load ${(cpu.load1||0).toFixed(2)} · ${(cpu.load5||0).toFixed(2)} · ${(cpu.load15||0).toFixed(2)}`;
const mem=m.mem||{};$('#mMem').textContent=(mem.usedPct||0).toFixed(0)+'%';$('#mMemBar').innerHTML=barPct(mem.usedPct||0);$('#mMemSub').textContent=`${mem.usedMB||0} / ${mem.totalMB||0} MB`;
const ct=m.conntrack||{};const ctPct=ct.max?100*ct.count/ct.max:0;$('#mCt').textContent=(ct.count||0).toLocaleString('hr-HR');$('#mCtBar').innerHTML=barPct(ctPct);$('#mCtSub').textContent=ct.max?`od ${ct.max.toLocaleString('hr-HR')} (${ctPct.toFixed(0)}%)`:'nedostupno';
$('#mUp').textContent=fmtUptime(m.uptimeSec||0);
const cores=cpu.cores||[];$('#mCores').innerHTML=cores.length?cores.map((c,i)=>`<div class="core"><span class="muted">c${i}</span>${barPct(c)}<span class="cnum">${c.toFixed(0)}%</span></div>`).join(''):'<span class="muted">nedostupno (razvojno okruženje)</span>';
const ifs=m.interfaces||[],prev=lastMetric,dt=prev?Math.max(1,m.ts-prev.ts):0,pmap={};if(prev)(prev.interfaces||[]).forEach(p=>pmap[p.name]=p);
$('#mIf').innerHTML=ifs.length?ifs.map(f=>{let rx=0,tx=0;const p=pmap[f.name];if(p&&dt>0){rx=(f.rxBytes-p.rxBytes)*8/dt;tx=(f.txBytes-p.txBytes)*8/dt}const link=f.carrier?`<span class="status st-healthy">up${f.speedMb?' · '+f.speedMb+'Mb':''}</span>`:'<span class="status st-muted">down</span>';return `<tr><td><b>${escapeHtml(nlabel(f.name))}</b></td><td>${f.role?`<span class="badge">${escapeHtml(f.role)}</span>`:''}</td><td>${link}</td><td>${fmtRate(rx)}</td><td>${fmtRate(tx)}</td></tr>`}).join(''):'<tr><td colspan="5" class="muted">nedostupno</td></tr>';
lastMetric=m;if(dashTick%5===0)refreshLogs();dashTick++}
async function checkService(id){try{const r=await api(`/api/services/${id}/actions/check`,{method:'POST',body:'{}'});alert(`${r.result.id}: ${r.result.status}\n${r.result.detail||''} (${r.result.latencyMs} ms)`);openModule(current)}catch(e){alert(e.message)}}
async function monitoring(){const rows=await api('/api/events?limit=100');$('#content').innerHTML=`<div class="panel scroll"><h2>Događaji (zadnjih ${rows.length})</h2><table><thead><tr><th>Vrijeme</th><th>Razina</th><th>Modul</th><th>Akcija</th><th>Poruka</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${new Date(x.ts).toLocaleString()}</td><td class="sev-${escapeHtml(x.severity||'info')}">${escapeHtml(x.severity)}</td><td>${escapeHtml(x.module)}</td><td>${escapeHtml(x.action||'')}</td><td>${escapeHtml(x.message)}</td></tr>`).join('')}</tbody></table></div>`}
const ROLES=['admin','network-operator','dns-operator','auditor','read-only'];
// Port forward line: proto:extPort:IP:port  OR (bound to a public IP)
// proto:extIP:extPort:IP:port. A 5th field (the extra IP) is the public address.
const pfParse=t=>t.split(/[\n,]/).map(s=>s.trim()).filter(Boolean).map(s=>{const p=s.split(':');return p.length>=5?{proto:p[0],extIp:p[1],extPort:parseInt(p[2],10),destIp:p[3],destPort:parseInt(p[4],10)}:{proto:p[0],extPort:parseInt(p[1],10),destIp:p[2],destPort:parseInt(p[3],10)}});
async function gatewayPage(){const g=await api('/api/gateway');const c=g.config||{};let wans=((await api('/api/wan').catch(()=>({wans:[]}))).wans)||[];const ew=escapeHtml;
// NAT rules edited as structured rows (mutated in place, persisted on Spremi/Primijeni via payload()).
let pf=(c.portForwards||[]).map(x=>({...x})),snat=(c.snatRules||[]).map(x=>({...x})),nat11=(c.nat11||[]).map(x=>({...x}));
// Sensible defaults from the box's own ports (stable names lan0/wan1) so the
// form is nearly one-click on a fresh gateway instead of empty.
const nb=n=>(g.nics||[]).find(z=>z.name===n)||null;
const lanN=nb('lan0'),wanN=nb('wan1');
const lanAddr=(lanN&&(lanN.addresses||[])[0])||'';
const defClient=c.clientNetwork||cidrNetwork(lanAddr);
const defWan=c.wanInterface||(wanN?'wan1':'');
const defLan=c.lanInterface||(lanN?'lan0':'');
const defDhcp=c.dhcpInterface||(lanN?'lan0':'');
const nicOpt=v=>(g.nics||[]).map(n=>`<option value="${ew(n.name)}" ${n.name===v?'selected':''}>${ew(nlabel(n.name))}</option>`).join('')||(v?`<option selected>${ew(v)}</option>`:'<option value="">—</option>');
const nicOptBlank=v=>`<option value="">— nijedno —</option>`+(g.nics||[]).map(n=>`<option value="${ew(n.name)}" ${n.name===v?'selected':''}>${ew(nlabel(n.name))}</option>`).join('');
const nicsTable=`<table class="compact"><thead><tr><th>Port</th><th>Stanje</th><th>IPv4</th></tr></thead><tbody>${(g.nics||[]).map(n=>`<tr><td><b>${ew(nlabel(n.name))}</b></td><td>${ew(n.state)}</td><td class="muted">${ew((n.addresses||[]).join(', ')||'—')}</td></tr>`).join('')||'<tr><td colspan="3" class="muted">Nema podataka o portovima.</td></tr>'}</tbody></table>`;
const wanPanel=`<div class="panel"><h2>WAN veze</h2>
${help('Postavi JEDNU ili VIŠE WAN veza (npr. WAN1 + GSM WAN2). Svaka je <b>DHCP</b> ili <b>statička</b> (IP/CIDR + gateway + DNS + aliasi). <b>Metrika</b> je prioritet default rute — manja = primarni WAN. Za balans/failover preko oba uključi modul <b>Multi-WAN</b>. Promjena piše netplan i radi <code>netplan apply</code>; mgmt pristup ide preko svog porta pa GUI ne puca.')}
<div class="btnrow" style="justify-content:flex-end;flex-wrap:wrap"><button type="button" id="wanNew" class="ghost">+ Dodaj WAN vezu</button> <button type="button" id="wanAddIp" class="ghost">+ Dodaj IP adresu</button> <button type="button" id="wanApplyBtn">Primijeni WAN veze</button></div>
<div id="wanStatus" class="muted small" style="margin:.2rem 0"></div>
<div id="wanIpForm" class="stack" style="display:none;border:1px solid var(--line,#394150);border-radius:8px;padding:.6rem .8rem;margin:.4rem 0">
<label>WAN port <select id="ipPort"></select></label>
<label>IP adresa (CIDR) <input id="ipAddr" placeholder="203.0.113.6/24"></label>
<div style="display:flex;gap:1.2rem;flex-wrap:wrap">
<label class="radio"><input type="radio" name="ipKind" value="alias" checked> <span><b>Alias</b> — dodatna javna IP</span></label>
<label class="radio"><input type="radio" name="ipKind" value="primary"> <span><b>Glavna</b> — primarna (port postaje statički)</span></label>
</div>
<div id="ipGwWrap" style="display:none"><label>Gateway (za glavnu adresu) <input id="ipGw" placeholder="203.0.113.1"></label></div>
<div class="btnrow"><button type="button" id="ipSave">Spremi IP</button> <button type="button" id="ipCancel" class="ghost">Odustani</button></div>
<div id="ipMsg" class="muted small"></div></div>
<div id="wanList"></div>
<form id="wanForm" class="stack" style="display:none;border:1px solid var(--line,#394150);border-radius:8px;padding:.7rem .9rem;margin:.4rem 0">
<h3 id="wanFormTitle" style="margin:.1rem 0 .3rem">Nova WAN veza</h3>
<label>WAN port <select id="wanIf"><option value="">— odaberi port —</option>${(g.nics||[]).map(n=>`<option value="${ew(n.name)}">${ew(nlabel(n.name))}</option>`).join('')}</select></label>
<label>Način adrese <select id="wanMode"><option value="dhcp">Dinamička (DHCP)</option><option value="static">Statička</option></select></label>
<label>Metrika (manja = primarni) <input id="wanMetric" type="number" min="1" max="4000" value="100"></label>
<div id="wanStatic" style="display:none">
<label>IP adresa (CIDR) <input id="wanAddr" placeholder="203.0.113.5/24"></label>
<label>Gateway <input id="wanGw" placeholder="203.0.113.1"></label>
<label>DNS serveri (zarezom) <input id="wanDns" placeholder="1.1.1.1, 8.8.8.8"></label>
</div>
<div class="btnrow"><button type="submit" id="wanAddBtn">Spremi u listu</button> <button type="button" id="wanCancel" class="ghost">Odustani</button></div>
<div id="wanMsg" class="muted small"></div></form></div>`;
const gwPanel=`<div class="panel"><h2>Gateway / NAT</h2>
${help('<b>Portovi:</b> odaberi <b>WAN port</b> (prema internetu) i <b>LAN port</b> (prema klijentima). Ne znaš koji je koji fizički? Otvori <b>Mreža → Interfaces</b> i klikni Identificiraj (LED zatreperi). <b>LAN / klijentska mreža</b> je subnet koji kutija poslužuje (DHCP/DNS) — sam se popuni iz LAN porta. <b>Gateway mod</b> uključuje routing WAN↔LAN, <b>NAT</b> pušta klijente na internet preko WAN adrese. <b>Pristup upravljanju</b>: biraš odgovara li kutija na SSH/GUI s LAN i/ili WAN strane; barem jedan mora ostati. <b>Port forward</b> (napredno) otvara vanjski port prema unutarnjem poslužitelju. Primjena traži potvrdu unutar 120 s — ako izgubiš pristup, vraća se stara konfiguracija.')}
<form id="gwForm" class="stack">
<label>WAN port (prema internetu) <select id="gwWan">${nicOpt(defWan)}</select></label>
<label>LAN port (prema klijentima) <select id="gwLan">${nicOpt(defLan)}</select></label>
<label>LAN port koji poslužuje DHCP <select id="gwDhcpIf">${nicOptBlank(defDhcp)}</select></label>
<label>LAN / klijentska mreža (CIDR) <input id="gwClient" value="${ew(defClient)}" placeholder="10.10.10.0/24" required></label>
${toggle('gwEnabled',c.gatewayEnabled,'Gateway mod (routing WAN↔LAN)')}
${toggle('gwNat',c.natEnabled!==false,'NAT (masquerade) na WAN')}
<h3>Pristup upravljanju (SSH / GUI)</h3>
${toggle('gwMgmtLan',c.mgmtOnLan!==false,'Dostupno s LAN strane')}
${toggle('gwMgmtWan',c.mgmtOnWan===true,'Dostupno s WAN strane')}
<label>Dodatna mgmt mreža (CIDR) — opcionalno <input id="gwAdmin" value="${ew(c.adminNetwork||'')}" placeholder="npr. 192.168.10.0/24"></label>
<p class="muted small">Sivi tekst je samo primjer (placeholder) — ostavi prazno ako koristiš prekidače gore. Barem jedan pristup mora ostati uključen.</p>
<h3>Napredno</h3>
${toggle('gwHairpin',c.hairpinNat,'Hairpin NAT (LAN klijenti dosežu port-forward preko javnog IP-a)')}
<h4>Preusmjeravanje portova (port forward · DNAT)</h4>
<p class="muted small">Otvara vanjski port prema unutarnjem poslužitelju. Ako imaš <b>više javnih IP-ova</b> na WAN-u, upiši <b>javnu IP</b> da vežeš pravilo baš za nju (prazno = vrijedi za WAN adresu). Javnu IP dodaj i kao WAN alias.</p>
<div id="pfList"></div>
<div class="filterbar"><select id="pfProto"><option value="tcp">tcp</option><option value="udp">udp</option></select><input id="pfExtIp" placeholder="javna IP (opcionalno)" style="max-width:170px"><input id="pfExtPort" type="number" min="1" max="65535" placeholder="vanjski port" style="max-width:130px"><span class="muted">→</span><input id="pfDestIp" placeholder="interna IP" style="max-width:150px"><input id="pfDestPort" type="number" min="1" max="65535" placeholder="interni port" style="max-width:130px"><button type="button" id="pfAddBtn" class="ghost">Dodaj</button><button type="button" id="pfCancel" class="ghost" style="display:none">Odustani</button></div>
<div id="pfMsg" class="muted small"></div>
<h4>Izlaz preko određene javne IP (SNAT)</h4>
<p class="muted small">Neka <b>određeni</b> host/mreža izlazi na internet pod točno određenom javnom adresom (umjesto zajedničke). Javna IP mora biti dodana kao WAN alias.</p>
<div id="snList"></div>
<div class="filterbar"><input id="snSrc" placeholder="izvor (IP ili CIDR)" style="max-width:200px"><span class="muted">→</span><input id="snTo" placeholder="javna IP" style="max-width:170px"><button type="button" id="snAddBtn" class="ghost">Dodaj</button><button type="button" id="snCancel" class="ghost" style="display:none">Odustani</button></div>
<div id="snMsg" class="muted small"></div>
<h4>1:1 NAT — cijela javna IP ↔ jedan interni host</h4>
<p class="muted small">Sav <b>ulazni</b> promet na javnu IP ide na interni host, a taj host <b>izlazi</b> pod tom istom javnom IP — u oba smjera, svi portovi. Javnu IP dodaj i kao <b>WAN alias</b>. Za sigurnost dalje suzi firewall pravilima.</p>
<div id="n11List"></div>
<div class="filterbar"><input id="n11Ext" placeholder="javna IP" style="max-width:170px"><span class="muted">↔</span><input id="n11Int" placeholder="interna IP" style="max-width:170px"><button type="button" id="n11AddBtn" class="ghost">Dodaj</button><button type="button" id="n11Cancel" class="ghost" style="display:none">Odustani</button></div>
<div id="n11Msg" class="muted small"></div>
<div class="btnrow"><button type="submit">Spremi</button> <button type="button" id="gwPreview" class="ghost">Pregled pravila</button> <button type="button" id="gwApply">Primijeni (120 s potvrda)</button></div>
<div id="gwMsg" class="muted"></div><pre id="gwRules" class="muted" style="white-space:pre-wrap"></pre></form></div>`;
const pend=g.pending?`<div class="panel error"><h2>⚠ Promjena firewalla čeka potvrdu</h2><p>Novi ruleset je aktivan. Bez potvrde unutar 120 sekundi vraća se prethodna konfiguracija.</p><div class="btnrow"><button id="gwConfirm">Potvrdi (zadrži)</button> <button id="gwRollback" class="ghost">Vrati odmah</button></div></div>`:'';
$('#content').innerHTML=`${pend}
${tabBar('gwTabs',[['wan','WAN veze'],['nat','Gateway / NAT']])}
<div class="tabpane active" data-pane="gwTabs" data-tabkey="wan"><div class="panel"><h2>Mrežni portovi</h2>${nicsTable}</div>${wanPanel}</div>
<div class="tabpane" data-pane="gwTabs" data-tabkey="nat">${gwPanel}</div>`;
wireTabs('gwTabs');
const payload=()=>({adminNetwork:$('#gwAdmin').value.trim(),clientNetwork:$('#gwClient').value.trim(),dhcpInterface:$('#gwDhcpIf').value.trim(),gatewayEnabled:$('#gwEnabled').checked,wanInterface:$('#gwWan').value,lanInterface:$('#gwLan').value,natEnabled:$('#gwNat').checked,mgmtOnLan:$('#gwMgmtLan').checked,mgmtOnWan:$('#gwMgmtWan').checked,hairpinNat:$('#gwHairpin').checked,portForwards:pf,snatRules:snat,nat11:nat11});
const save=async()=>{await api('/api/gateway',{method:'PUT',body:JSON.stringify(payload())})};
const ipOf=name=>{const n=(g.nics||[]).find(z=>z.name===name);return (n&&(n.addresses||[])[0])||''};
const modeLabel=m=>m==='static'?'Statička':'Dinamička (DHCP)';
let wanEdit=-1,ipEdit=null;
const primaryOf=x=>x.mode==='static'?(x.address||'—'):(ipOf(x.interface)||'(DHCP — čeka lease)');
const renderWanList=()=>{const ips=$('#ipPort');if(ips){const cur=ips.value;ips.innerHTML=wans.map(w=>`<option value="${ew(w.interface)}">${ew(nlabel(w.interface))}</option>`).join('');if(cur&&wans.some(w=>w.interface===cur))ips.value=cur}
$('#wanList').innerHTML=wans.length?wans.map((x,i)=>{const aliasRows=(x.aliases||[]).map((a,ai)=>`<li style="display:flex;align-items:center;gap:.5rem;padding:.15rem 0"><code>${ew(a)}</code> ${iconBtn('edit','Uredi alias','alE','data-i="'+i+'" data-a="'+ai+'"')}${iconBtn('del','Obriši alias','danger alD','data-i="'+i+'" data-a="'+ai+'"')} <span class="muted small">alias</span></li>`).join('');return `<div style="border:1px solid var(--line,#394150);border-radius:8px;padding:.5rem .7rem;margin:.45rem 0"><div style="display:flex;justify-content:space-between;align-items:center;gap:.5rem;flex-wrap:wrap"><span><b>${ew(nlabel(x.interface))}</b> <span class="muted small">· ${ew(modeLabel(x.mode))} · metrika ${x.metric||100}</span></span><span class="rowacts"><button class="wanEdit ghost" data-i="${i}">Uredi vezu</button> <button class="wanRm danger" data-i="${i}">Ukloni WAN</button></span></div><ul style="list-style:none;margin:.35rem 0 0;padding:0"><li style="display:flex;align-items:center;gap:.5rem;padding:.15rem 0"><code>${ew(primaryOf(x))}</code> <span class="muted small">glavna, ${x.mode==='static'?'statička':'DHCP'}${x.mode==='static'&&x.gateway?' · gw '+ew(x.gateway):''}</span></li>${aliasRows}</ul></div>`}).join(''):'<p class="muted">Nema konfiguriranih WAN veza.</p>';
document.querySelectorAll('.wanRm').forEach(el=>el.onclick=()=>{wans.splice(+el.dataset.i,1);if(wanEdit>=0)wanReset();renderWanList()});
document.querySelectorAll('.alD').forEach(el=>el.onclick=()=>{const i=+el.dataset.i,ai=+el.dataset.a;wans[i].aliases.splice(ai,1);if(ipEdit)ipReset();renderWanList()});
document.querySelectorAll('.alE').forEach(el=>el.onclick=()=>{const i=+el.dataset.i,ai=+el.dataset.a;ipEdit={wi:i,ai:ai};$('#wanIpForm').style.display='';$('#wanAddIp').style.display='none';$('#ipPort').value=wans[i].interface;$('#ipAddr').value=wans[i].aliases[ai];document.querySelector('input[name=ipKind][value=alias]').checked=true;$('#ipGwWrap').style.display='none';$('#ipSave').textContent='Spremi izmjene';$('#ipMsg').textContent='Uređuješ alias.'});
document.querySelectorAll('.wanEdit').forEach(el=>el.onclick=()=>{const i=+el.dataset.i,x=wans[i];const sel=$('#wanIf');
// A stored uplink can name a port this box no longer has (a NIC moved, or the
// configuration came from other hardware). Keep it selectable instead of
// silently blanking the field, which would rewrite the row on the next save.
if(x.interface&&![...sel.options].some(o=>o.value===x.interface)){sel.add(new Option(x.interface+' (nedostupan)',x.interface))}
if(ipEdit)ipReset();$('#wanIpForm').style.display='none';$('#wanAddIp').style.display='';wanEdit=i;sel.value=x.interface;$('#wanMode').value=x.mode;$('#wanMetric').value=x.metric||100;$('#wanAddr').value=x.address||'';$('#wanGw').value=x.gateway||'';$('#wanDns').value=(x.dns||[]).join(', ');$('#wanStatic').style.display=x.mode==='static'?'':'none';$('#wanAddBtn').textContent='Spremi izmjene';$('#wanMsg').textContent='';wanDrawer.edit('Uredi WAN vezu — '+nlabel(x.interface))});};
renderWanList();
// Structured NAT editor: three in-place tables (port-forward / SNAT / 1:1) with
// per-row edit + delete. Rows mutate pf/snat/nat11, persisted via payload() on Spremi/Primijeni.
let pfEdit=-1,snEdit=-1,n11Edit=-1;
const natActs=(cls,i)=>`<div class="rowacts">${iconBtn('edit','Uredi','',`data-i="${i}"`).replace('iconbtn','iconbtn '+cls+'E')}${iconBtn('del','Obriši','danger',`data-i="${i}"`).replace('iconbtn','iconbtn '+cls+'D')}</div>`;
const renderNat=()=>{
$('#pfList').innerHTML=pf.length?`<table class="compact"><thead><tr><th>Proto</th><th>Vanjski</th><th>Interno</th><th></th></tr></thead><tbody>${pf.map((p,i)=>`<tr><td>${ew(p.proto)}</td><td class="muted">${ew(p.extIp||nlabel(defWan))}:${ew(String(p.extPort))}</td><td class="muted">${ew(p.destIp)}:${ew(String(p.destPort))}</td><td>${natActs('pf',i)}</td></tr>`).join('')}</tbody></table>`:'<p class="muted small">Nema port-forward pravila.</p>';
$('#snList').innerHTML=snat.length?`<table class="compact"><thead><tr><th>Izvor</th><th>Javna IP</th><th></th></tr></thead><tbody>${snat.map((r,i)=>`<tr><td>${ew(r.source)}</td><td class="muted">${ew(r.toAddress)}</td><td>${natActs('sn',i)}</td></tr>`).join('')}</tbody></table>`:'<p class="muted small">Nema SNAT pravila.</p>';
$('#n11List').innerHTML=nat11.length?`<table class="compact"><thead><tr><th>Javna IP</th><th>Interna IP</th><th></th></tr></thead><tbody>${nat11.map((r,i)=>`<tr><td>${ew(r.extIp)}</td><td class="muted">${ew(r.intIp)}</td><td>${natActs('n11',i)}</td></tr>`).join('')}</tbody></table>`:'<p class="muted small">Nema 1:1 NAT pravila.</p>';
document.querySelectorAll('.pfD').forEach(el=>el.onclick=()=>{pf.splice(+el.dataset.i,1);if(pfEdit>=0)pfReset();renderNat()});
document.querySelectorAll('.snD').forEach(el=>el.onclick=()=>{snat.splice(+el.dataset.i,1);if(snEdit>=0)snReset();renderNat()});
document.querySelectorAll('.n11D').forEach(el=>el.onclick=()=>{nat11.splice(+el.dataset.i,1);if(n11Edit>=0)n11Reset();renderNat()});
document.querySelectorAll('.pfE').forEach(el=>el.onclick=()=>{const p=pf[+el.dataset.i];pfEdit=+el.dataset.i;$('#pfProto').value=p.proto||'tcp';$('#pfExtIp').value=p.extIp||'';$('#pfExtPort').value=p.extPort||'';$('#pfDestIp').value=p.destIp||'';$('#pfDestPort').value=p.destPort||'';$('#pfAddBtn').textContent='Spremi';$('#pfCancel').style.display='';$('#pfMsg').textContent='Uređuješ port-forward.'});
document.querySelectorAll('.snE').forEach(el=>el.onclick=()=>{const r=snat[+el.dataset.i];snEdit=+el.dataset.i;$('#snSrc').value=r.source||'';$('#snTo').value=r.toAddress||'';$('#snAddBtn').textContent='Spremi';$('#snCancel').style.display='';$('#snMsg').textContent='Uređuješ SNAT.'});
document.querySelectorAll('.n11E').forEach(el=>el.onclick=()=>{const r=nat11[+el.dataset.i];n11Edit=+el.dataset.i;$('#n11Ext').value=r.extIp||'';$('#n11Int').value=r.intIp||'';$('#n11AddBtn').textContent='Spremi';$('#n11Cancel').style.display='';$('#n11Msg').textContent='Uređuješ 1:1 NAT.'})};
const pfReset=()=>{pfEdit=-1;['pfExtIp','pfExtPort','pfDestIp','pfDestPort'].forEach(id=>$('#'+id).value='');$('#pfAddBtn').textContent='Dodaj';$('#pfCancel').style.display='none';$('#pfMsg').textContent=''};
const snReset=()=>{snEdit=-1;$('#snSrc').value='';$('#snTo').value='';$('#snAddBtn').textContent='Dodaj';$('#snCancel').style.display='none';$('#snMsg').textContent=''};
const n11Reset=()=>{n11Edit=-1;$('#n11Ext').value='';$('#n11Int').value='';$('#n11AddBtn').textContent='Dodaj';$('#n11Cancel').style.display='none';$('#n11Msg').textContent=''};
$('#pfCancel').onclick=pfReset;$('#snCancel').onclick=snReset;$('#n11Cancel').onclick=n11Reset;
$('#pfAddBtn').onclick=()=>{const m=$('#pfMsg');const proto=$('#pfProto').value,extIp=$('#pfExtIp').value.trim(),extPort=parseInt($('#pfExtPort').value,10)||0,destIp=$('#pfDestIp').value.trim(),destPort=parseInt($('#pfDestPort').value,10)||0;
if(extIp&&!isIPv4(extIp)){m.textContent='Javna IP mora biti IPv4 (ili prazno).';return}
if(extPort<1||extPort>65535){m.textContent='Vanjski port mora biti 1-65535.';return}
if(!isIPv4(destIp)){m.textContent='Interna IP mora biti IPv4.';return}
if(destPort<1||destPort>65535){m.textContent='Interni port mora biti 1-65535.';return}
const item={proto,extPort,destIp,destPort};if(extIp)item.extIp=extIp;
if(pfEdit>=0){pf[pfEdit]=item}else{pf.push(item)}pfReset();renderNat()};
$('#snAddBtn').onclick=()=>{const m=$('#snMsg');const source=$('#snSrc').value.trim(),toAddress=$('#snTo').value.trim();
if(!isIPv4(source)&&!isCIDR(source)){m.textContent='Izvor mora biti IPv4 ili CIDR.';return}
if(!isIPv4(toAddress)){m.textContent='Javna IP mora biti IPv4.';return}
const item={source,toAddress};if(snEdit>=0){snat[snEdit]=item}else{snat.push(item)}snReset();renderNat()};
$('#n11AddBtn').onclick=()=>{const m=$('#n11Msg');const extIp=$('#n11Ext').value.trim(),intIp=$('#n11Int').value.trim();
if(!isIPv4(extIp)){m.textContent='Javna IP mora biti IPv4.';return}
if(!isIPv4(intIp)){m.textContent='Interna IP mora biti IPv4.';return}
const item={extIp,intIp};if(n11Edit>=0){nat11[n11Edit]=item}else{nat11.push(item)}n11Reset();renderNat()};
renderNat();
$('#wanMode').onchange=()=>{$('#wanStatic').style.display=$('#wanMode').value==='static'?'':'none'};
const wanReset=()=>{wanEdit=-1;['wanIf','wanAddr','wanGw','wanDns'].forEach(id=>$('#'+id).value='');$('#wanMetric').value=100;$('#wanMode').value='dhcp';$('#wanStatic').style.display='none';$('#wanAddBtn').textContent='Spremi u listu';$('#wanFormTitle').textContent='Nova WAN veza';$('#wanForm').style.display='none';$('#wanMsg').textContent=''};
const wanDrawer=makeDrawer({form:'wanForm',title:'wanFormTitle',cancel:'wanCancel',addTitle:'Nova WAN veza',reset:wanReset,focus:'wanIf'});
$('#wanNew').onclick=()=>{if(ipEdit)ipReset();wanDrawer.add()};
$('#wanForm').onsubmit=e=>{e.preventDefault();const m=$('#wanMsg');const mode=$('#wanMode').value;const iface=$('#wanIf').value.trim();
if(!/^[a-zA-Z0-9._-]{1,15}$/.test(iface)){m.textContent='Odaberi WAN port.';return}
const wn={interface:iface,mode,metric:parseInt($('#wanMetric').value,10)||100,dns:$('#wanDns').value.split(',').map(x=>x.trim()).filter(Boolean),aliases:wanEdit>=0?(wans[wanEdit].aliases||[]):[]};
if(mode==='static'){wn.address=$('#wanAddr').value.trim();wn.gateway=$('#wanGw').value.trim();if(!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(wn.address)){m.textContent='IP adresa mora biti CIDR (npr. 203.0.113.5/24).';return}if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(wn.gateway)){m.textContent='Gateway mora biti IPv4 adresa.';return}}
if(wans.some((x,j)=>x.interface===iface&&j!==wanEdit)){m.textContent='To sučelje je već u listi.';return}
if(wanEdit>=0){wans[wanEdit]=wn}else{wans.push(wn)}wanReset();renderWanList();$('#wanStatus').textContent='Spremljeno u listu — klikni „Primijeni WAN veze".'};
const ipReset=()=>{ipEdit=null;$('#wanIpForm').style.display='none';$('#wanAddIp').style.display='';$('#ipAddr').value='';$('#ipGw').value='';const a=document.querySelector('input[name=ipKind][value=alias]');if(a)a.checked=true;$('#ipGwWrap').style.display='none';$('#ipSave').textContent='Spremi IP';$('#ipMsg').textContent=''};
$('#wanAddIp').onclick=()=>{if(!wans.length){$('#wanStatus').textContent='Prvo dodaj WAN vezu (port).';return}wanReset();ipEdit=null;renderWanList();$('#wanIpForm').style.display='';$('#wanAddIp').style.display='none';$('#ipAddr').value='';$('#ipGwWrap').style.display='none';$('#ipMsg').textContent=''};
$('#ipCancel').onclick=ipReset;
[...document.getElementsByName('ipKind')].forEach(r=>r.onchange=()=>{$('#ipGwWrap').style.display=(document.querySelector('input[name=ipKind]:checked').value==='primary')?'':'none'});
$('#ipSave').onclick=()=>{const m=$('#ipMsg');const port=$('#ipPort').value;const addr=$('#ipAddr').value.trim();const kind=document.querySelector('input[name=ipKind]:checked').value;const wi=wans.findIndex(w=>w.interface===port);if(wi<0){m.textContent='Odaberi WAN port.';return}
if(!isCIDR(addr)){m.textContent='IP adresa mora biti u CIDR obliku (npr. 203.0.113.6/24).';return}
if(kind==='primary'){const gw=$('#ipGw').value.trim()||wans[wi].gateway||'';if(!isIPv4(gw)){m.textContent='Glavna adresa treba gateway (IPv4 adresa).';return}if(ipEdit){wans[ipEdit.wi].aliases.splice(ipEdit.ai,1)}wans[wi].mode='static';wans[wi].address=addr;wans[wi].gateway=gw}
else{const dupPrimary=(wans[wi].mode==='static'&&wans[wi].address===addr);const dupAlias=(wans[wi].aliases||[]).some((a,k)=>a===addr&&!(ipEdit&&ipEdit.wi===wi&&ipEdit.ai===k));if(dupPrimary||dupAlias){m.textContent='Ta adresa već postoji na tom portu.';return}if(ipEdit){wans[ipEdit.wi].aliases.splice(ipEdit.ai,1)}(wans[wi].aliases=wans[wi].aliases||[]).push(addr)}
ipReset();renderWanList();$('#wanStatus').textContent='IP spremljen u listu — klikni „Primijeni WAN veze".'};
$('#wanApplyBtn').onclick=async()=>{const m=$('#wanStatus');if(!wans.length){m.textContent='Dodaj barem jedno WAN sučelje.';return}if(!confirm('Primijeniti sva WAN sučelja? Piše netplan i radi netplan apply.'))return;m.textContent='Primjena…';try{await api('/api/wan/apply',{method:'POST',body:JSON.stringify({wans})});m.textContent='WAN sučelja primijenjena.'}catch(err){m.textContent=err.message}};
$('#gwForm').onsubmit=async e=>{e.preventDefault();$('#gwMsg').textContent='';try{await save();$('#gwMsg').textContent='Spremljeno (još nije primijenjeno).'}catch(err){$('#gwMsg').textContent=err.message}};
$('#gwPreview').onclick=async()=>{try{await save();const p=await api('/api/gateway/preview');$('#gwRules').textContent=p.ruleset}catch(err){$('#gwMsg').textContent=err.message}};
$('#gwApply').onclick=async()=>{if(!confirm('Primijeniti novi firewall? Ako izgubite pristup, za 120 sekundi vraća se stara konfiguracija.'))return;$('#gwMsg').textContent='Primjena…';try{await save();await api('/api/gateway/apply',{method:'POST',body:'{}'});gatewayPage()}catch(err){$('#gwMsg').textContent=err.message}};
if(g.pending){$('#gwConfirm').onclick=async()=>{try{await api('/api/gateway/confirm',{method:'POST',body:'{}'});gatewayPage()}catch(err){alert(err.message)}};$('#gwRollback').onclick=async()=>{try{await api('/api/gateway/rollback',{method:'POST',body:'{}'});gatewayPage()}catch(err){alert(err.message)}}}}
async function wizGateway(){const g=await api('/api/gateway');const nics=g.nics||[];const c=g.config||{};
if(nics.length<2){alert('W8 zahtijeva najmanje 2 mrežna sučelja (WAN + LAN). Pronađeno: '+nics.length);return}
const opt=(v,ex)=>nics.filter(n=>n.name!==ex).map(n=>`<option ${n.name===v?'selected':''}>${escapeHtml(n.name)}</option>`).join('');
runWizard('Čarobnjak: Gateway conversion (W8)',[
{title:'Preduvjeti',render:s=>`<p>Pronađeno ${nics.length} sučelja: <b>${escapeHtml(nics.map(n=>n.name+' ('+n.state+')').join(', '))}</b></p><p class="error">Upozorenje: pretvorba u gateway mijenja topologiju mreže. Promjena se primjenjuje uz 120-sekundni prozor za potvrdu — ako izgubite pristup, stara konfiguracija se vraća automatski.</p>`},
{title:'WAN',render:s=>`<label>WAN (prema internetu) <select id="wgWan">${opt(s.wan)}</select></label>`,collect:s=>{s.wan=$('#wgWan').value;return s.wan?null:'Odaberite WAN.'}},
{title:'LAN i NAT',render:s=>`<label>LAN (lokalna mreža) <select id="wgLan">${opt(s.lan,s.wan)}</select></label><label><input id="wgNat" type="checkbox" ${s.nat!==false?'checked':''}> NAT (masquerade)</label>`,collect:s=>{s.lan=$('#wgLan').value;s.nat=$('#wgNat').checked;return s.lan&&s.lan!==s.wan?null:'Odaberite LAN različit od WAN-a.'}},
{title:'Mreže i port forwardi',render:s=>`<label>Mgmt mreža (CIDR) <input id="wgAdmin" value="${escapeHtml(s.admin||c.adminNetwork||'')}" placeholder="192.168.10.0/24"></label><label>Klijentska mreža (CIDR) <input id="wgClient" value="${escapeHtml(s.client||c.clientNetwork||'')}"></label><label>DHCP interface <input id="wgDhcpIf" value="${escapeHtml(s.dhcpIf||c.dhcpInterface||'')}"></label><label>Port forwardi (proto:vanjski:IP:unutarnji) <textarea id="wgPf" rows="3">${escapeHtml(s.pf||'')}</textarea></label>`,collect:s=>{s.admin=$('#wgAdmin').value.trim();s.client=$('#wgClient').value.trim();s.dhcpIf=$('#wgDhcpIf').value.trim();s.pf=$('#wgPf').value;return s.client?null:'Unesite klijentsku mrežu.'}},
{title:'Pregled i primjena',render:s=>`<p>WAN: <b>${escapeHtml(s.wan)}</b> · LAN: <b>${escapeHtml(s.lan)}</b> · NAT: <b>${s.nat?'da':'ne'}</b><br>Mgmt: <b>${escapeHtml(s.admin)}</b> · Klijenti: <b>${escapeHtml(s.client)}</b><br>Port forwardi: <b>${escapeHtml(s.pf.trim()||'—')}</b></p><p class="error">Primjenom se učitava novi nftables ruleset s prozorom za potvrdu od 120 s.</p>`}],
async s=>{await api('/api/gateway',{method:'PUT',body:JSON.stringify({adminNetwork:s.admin,clientNetwork:s.client,dhcpInterface:s.dhcpIf,gatewayEnabled:true,wanInterface:s.wan,lanInterface:s.lan,natEnabled:s.nat,mgmtOnLan:true,portForwards:pfParse(s.pf)})});await api('/api/gateway/apply',{method:'POST',body:'{}'});openModule('gateway')})}
async function usersPage(){const me=await api('/api/profile');let list=null;try{list=await api('/api/users')}catch(e){list=null}
const mine=`<div class="panel"><h2>Moj račun</h2><p>Korisnik: <b>${escapeHtml(me.username)}</b> — uloga: <b>${escapeHtml(me.role)}</b></p>
<form id="pwForm" class="stack"><h3>Promjena lozinke</h3><label>Trenutna lozinka <input id="pwOld" type="password" required></label><label>Nova lozinka (min. 14 znakova) <input id="pwNew" type="password" minlength="14" required></label><div><button type="submit">Promijeni</button></div><div id="pwMsg" class="muted"></div></form></div>`;
const admin=list===null?'':`<div class="panel"><h2>Korisnici (${list.length})</h2><table><thead><tr><th>Korisnik</th><th>Uloga</th><th>Aktivan</th><th></th></tr></thead><tbody>${list.map(u=>`<tr><td>${escapeHtml(u.username)}</td><td><select class="uRole" data-u="${escapeHtml(u.username)}">${ROLES.map(r=>`<option ${r===u.role?'selected':''}>${r}</option>`).join('')}</select></td><td>${u.enabled?'da':'ne'}</td><td><button class="uToggle" data-u="${escapeHtml(u.username)}" data-e="${u.enabled?1:0}">${u.enabled?'Onemogući':'Omogući'}</button> <button class="uReset" data-u="${escapeHtml(u.username)}">Reset lozinke</button> <button class="uDel" data-u="${escapeHtml(u.username)}">Obriši</button></td></tr>`).join('')}</tbody></table>
<form id="uAdd" class="stack"><h3>Novi korisnik</h3><label>Korisničko ime <input id="uName" required></label><label>Lozinka (min. 14) <input id="uPass" type="password" minlength="14" required></label><label>Uloga <select id="uNewRole">${ROLES.map(r=>`<option>${r}</option>`).join('')}</select></label><div><button type="submit">Dodaj</button></div><div id="uMsg" class="muted"></div></form></div>`;
$('#content').innerHTML=mine+admin;
$('#pwForm').onsubmit=async e=>{e.preventDefault();$('#pwMsg').textContent='';try{await api('/api/profile/password',{method:'POST',body:JSON.stringify({oldPassword:$('#pwOld').value,newPassword:$('#pwNew').value})});$('#pwMsg').textContent='Lozinka promijenjena.';$('#pwOld').value='';$('#pwNew').value=''}catch(err){$('#pwMsg').textContent=err.message}};
if(list===null)return;
const patch=async(u,body)=>{try{await api(`/api/users/${encodeURIComponent(u)}`,{method:'PATCH',body:JSON.stringify(body)});usersPage()}catch(err){alert(err.message)}};
document.querySelectorAll('.uRole').forEach(el=>el.onchange=()=>patch(el.dataset.u,{role:el.value}));
document.querySelectorAll('.uToggle').forEach(el=>el.onclick=()=>patch(el.dataset.u,{enabled:el.dataset.e!=='1'}));
document.querySelectorAll('.uReset').forEach(el=>el.onclick=()=>{const p=prompt(`Nova lozinka za ${el.dataset.u} (min. 14 znakova):`);if(p)patch(el.dataset.u,{password:p})});
document.querySelectorAll('.uDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati korisnika ${el.dataset.u}?`))return;try{await api(`/api/users/${encodeURIComponent(el.dataset.u)}`,{method:'DELETE'});usersPage()}catch(err){alert(err.message)}});
$('#uAdd').onsubmit=async e=>{e.preventDefault();$('#uMsg').textContent='';try{await api('/api/users',{method:'POST',body:JSON.stringify({username:$('#uName').value.trim(),password:$('#uPass').value,role:$('#uNewRole').value})});usersPage()}catch(err){$('#uMsg').textContent=err.message}}}
async function backupPage(){const b=await api('/api/backup');
const drill=b.restoreDrillDue?`<div class="panel error"><h2>⚠ Restore drill</h2><p>Provjera povrata podataka nije izvedena u zadnjih ${b.restoreDrillDays} dana (${b.lastDrill&&!b.lastDrill.startsWith('0001')?'zadnja: '+new Date(b.lastDrill).toLocaleDateString():'nikad'}). Napravite testni restore pa potvrdite.</p><button id="bkDrill">Označi drill izvedenim</button></div>`:`<div class="panel"><p class="muted">Restore drill zadnji put: ${b.lastDrill&&!b.lastDrill.startsWith('0001')?new Date(b.lastDrill).toLocaleDateString():'—'} (podsjetnik svakih ${b.restoreDrillDays} dana). <button id="bkDrill">Označi drill izvedenim</button></p></div>`;
$('#content').innerHTML=`${drill}<div class="panel"><h2>Backup ${b.target!=='local'?'<span class="badge">'+escapeHtml(b.target)+'</span>':''}</h2>
<form id="bkForm" class="stack">
<label>Cilj <select id="bkTarget"><option value="local" ${b.target==='local'?'selected':''}>Lokalno</option><option value="sftp" ${b.target==='sftp'?'selected':''}>SFTP</option><option value="s3" ${b.target==='s3'?'selected':''}>S3</option></select></label>
<label>Raspored <select id="bkSched">${['hourly','daily','weekly','monthly'].map(x=>`<option ${b.schedule===x?'selected':''}>${x}</option>`).join('')}</select></label>
<label>Retencija (dana) <input id="bkRet" type="number" value="${b.retentionDays||30}" min="1"></label>
<fieldset id="bkSftp" style="border:1px solid var(--line);border-radius:8px;padding:12px"><legend>SFTP</legend><label>Host <input id="bkSHost" value="${escapeHtml(b.sftpHost||'')}"></label><label>Port <input id="bkSPort" type="number" value="${b.sftpPort||22}"></label><label>Korisnik <input id="bkSUser" value="${escapeHtml(b.sftpUser||'')}"></label><label>Putanja <input id="bkSPath" value="${escapeHtml(b.sftpPath||'')}" placeholder="/backups/saguaro"></label><label>Putanja SSH ključa na appliance-u <input id="bkSKey" placeholder="/etc/saguaro/backup-sftp.key"></label></fieldset>
<fieldset id="bkS3" style="border:1px solid var(--line);border-radius:8px;padding:12px"><legend>S3</legend><label>Bucket <input id="bkBucket" value="${escapeHtml(b.s3Bucket||'')}"></label><label>Endpoint (opc.) <input id="bkEndpoint" value="${escapeHtml(b.s3Endpoint||'')}" placeholder="https://s3.eu-central-1.amazonaws.com"></label><label>Regija <input id="bkRegion" value="${escapeHtml(b.s3Region||'us-east-1')}"></label><label>Access key ID <input id="bkAccess" value="${escapeHtml(b.s3AccessId||'')}"></label><label>Secret key ${b.hasSecret?'(spremljen)':''} <input id="bkSecret" type="password"></label></fieldset>
<div><button type="submit">Spremi</button> <button type="button" id="bkRun">Pokreni backup sada</button></div>
<p class="muted">Šifriranje je obavezno (age); off-site arhive su već šifrirane pa transport samo mora biti autenticiran.</p><div id="bkMsg" class="muted"></div></form></div>`;
const toggle=()=>{const t=$('#bkTarget').value;$('#bkSftp').style.display=t==='sftp'?'block':'none';$('#bkS3').style.display=t==='s3'?'block':'none'};toggle();$('#bkTarget').onchange=toggle;
if($('#bkDrill'))$('#bkDrill').onclick=async()=>{try{await api('/api/backup/drill',{method:'POST',body:'{}'});backupPage()}catch(e){alert(e.message)}};
$('#bkRun').onclick=async()=>{$('#bkMsg').textContent='Pokrećem…';try{await api('/api/backup/run',{method:'POST',body:'{}'});$('#bkMsg').textContent='Backup pokrenut.'}catch(e){$('#bkMsg').textContent=e.message}};
$('#bkForm').onsubmit=async e=>{e.preventDefault();$('#bkMsg').textContent='Primjena…';const body={target:$('#bkTarget').value,schedule:$('#bkSched').value,retentionDays:parseInt($('#bkRet').value,10)||30,sftpHost:$('#bkSHost').value.trim(),sftpPort:parseInt($('#bkSPort').value,10)||22,sftpUser:$('#bkSUser').value.trim(),sftpPath:$('#bkSPath').value.trim(),sftpKeyPath:$('#bkSKey').value.trim(),s3Bucket:$('#bkBucket').value.trim(),s3Endpoint:$('#bkEndpoint').value.trim(),s3Region:$('#bkRegion').value.trim(),s3AccessId:$('#bkAccess').value.trim(),s3Secret:$('#bkSecret').value};try{await api('/api/backup/apply',{method:'POST',body:JSON.stringify(body)});$('#bkMsg').textContent='Spremljeno.';$('#bkSecret').value=''}catch(err){$('#bkMsg').textContent=err.message}}}
async function multiwanPage(){const m=await api('/api/multiwan');let nics=[];try{nics=(await api('/api/gateway')).nics||[]}catch(e){}const e=escapeHtml;
// In-memory edit model — nothing touches routing until "Primijeni/Uključi".
let cfg={enabled:!!m.enabled,mode:m.mode||'loadbalance',uplinks:(m.uplinks||[]).map(u=>({...u}))};
const render=()=>{const fo=cfg.mode==='failover';
const roleBadge=(i)=>fo?(i===0?'<span class="badge" title="Primarni — sav promet dok je zdrav">Primarni</span>':i===1?'<span class="badge">Sekundarni</span>':`<span class="badge">Pričuva ${i+1}</span>`):`<span class="badge">težina ${cfg.uplinks[i].weight}</span>`;
const rows=cfg.uplinks.length?cfg.uplinks.map((u,i)=>{const reorder=fo?`${iconBtn('up','Prioritet gore','muwUp',`data-i="${i}"${i===0?' disabled':''}`)}${iconBtn('down','Prioritet dolje','muwDown',`data-i="${i}"${i===cfg.uplinks.length-1?' disabled':''}`)}`:'';return `<tr><td><b>${e(u.name)}</b></td><td class="muted">${e(nlabel(u.interface))}</td><td class="muted">${e(u.gateway)}</td><td>${roleBadge(i)}</td><td class="muted">${e(u.healthCheck||'—')}</td><td class="rowacts">${reorder}${iconBtn('edit','Uredi','muwEdit',`data-i="${i}"`)}${iconBtn('del','Ukloni','danger muwDel',`data-i="${i}"`)}</td></tr>`}).join(''):'<tr><td colspan="6" class="muted">Nema uplinkova — dodaj barem dva.</td></tr>';
$('#content').innerHTML=`${m.pending?`<div class="panel error"><h2>⚠ Multi-WAN čeka potvrdu</h2><p>Nova ruta i PBR su aktivni. Bez potvrde unutar <b>120 s</b> vraća se prethodna konfiguracija (auto-rollback) — štiti od gubitka pristupa pri promjeni rute.</p><div class="btnrow"><button id="wanConfirm">Potvrdi (zadrži)</button> <button id="wanRollback" class="ghost">Vrati odmah</button></div></div>`:''}
<div class="panel"><h2>Multi-WAN</h2>
<div style="margin:.1rem 0 .5rem;font-size:.95rem"><b>Trenutno stanje:</b> ${m.enabled?`<span class="status st-healthy">aktivan</span> · način <b>${m.mode==='failover'?'Failover (jedan aktivni)':'Load-balance (multipath)'}</b>`:'<span class="status st-muted">isključeno</span>'}${m.pending?' · <span class="status st-error">čeka potvrdu (120 s)</span>':''}</div>
${help('<b>Način:</b> <b>Failover</b> = točno JEDAN aktivni uplink; promet ide kroz <b>Primarni</b>, a na pad njegovog health-checka prebaci se na <b>Sekundarni</b> (pa se vrati kad primarni oživi). <b>Load-balance</b> = ponderirani multipath preko svih zdravih uplinkova (treba connmark za simetriju). <br><br>U failoveru <b>redoslijed = prioritet</b> (vrh = primarni; presloži strelicama), a težina se ignorira. <b>Health-check IP</b> je ono što se pinga po sučelju da se odluči je li uplink gore. Zahtijeva <b>Gateway mod</b>. Primjena mijenja default rutu uz <b>120 s potvrdu</b> (auto-rollback ako izgubiš pristup). Preporuka: simuliraj ispad primarnog prije produkcije.')}
<label>Način rada <select id="muwMode"><option value="failover" ${fo?'selected':''}>Failover — jedan aktivni uplink, ostali pričuva</option><option value="loadbalance" ${fo?'':'selected'}>Load-balance — ponderirani multipath</option></select></label>
<table><thead><tr><th>Naziv</th><th>Interface</th><th>Gateway</th><th>${fo?'Uloga (failover)':'Uloga (load-balance)'}</th><th>Health-check</th><th></th></tr></thead><tbody>${rows}</tbody></table>
<div class="btnrow"><button type="button" id="wanAdd" class="ghost">+ Dodaj uplink</button> <button type="button" id="wanApply" ${cfg.uplinks.length>=2?'':'disabled'}>${m.enabled?'Ponovno primijeni':'Uključi'}</button> ${m.enabled?'<button type="button" id="wanOff" class="ghost">Isključi</button>':''}</div>
<p class="muted small">Izmjene (način, redoslijed, dodaj/ukloni) primjenjuju se tek klikom na <b>Primijeni/Uključi</b>.</p>
<div id="wanMsg" class="muted"></div></div>`;
$('#muwMode').onchange=()=>{cfg.mode=$('#muwMode').value;render()};
$('#wanAdd').onclick=()=>{const opt=nics.map(n=>n.name).join(', ');const iface=prompt('Interface'+(opt?` (${opt})`:'')+':');if(!iface)return;const gw=prompt('Gateway IP:');if(!gw)return;const name=(prompt('Naziv veze:',iface)||iface).trim();const weight=fo?1:(parseInt(prompt('Težina (1-256):','1'),10)||1);const hc=(prompt('Health-check IP (prazno = bez):','1.1.1.1')||'').trim();cfg.uplinks.push({name,interface:iface.trim(),gateway:gw.trim(),weight,healthCheck:hc});render()};
document.querySelectorAll('.muwEdit').forEach(el=>el.onclick=()=>{const i=+el.dataset.i;const u=cfg.uplinks[i];const name=(prompt('Naziv veze:',u.name)||u.name).trim();const iface=(prompt('Interface:',u.interface)||u.interface).trim();const gw=(prompt('Gateway IP:',u.gateway)||u.gateway).trim();const hc=(prompt('Health-check IP (prazno = bez):',u.healthCheck||'')||'').trim();let weight=u.weight;if(!fo){weight=parseInt(prompt('Težina (1-256):',String(u.weight||1)),10)||u.weight||1}cfg.uplinks[i]={...u,name,interface:iface,gateway:gw,healthCheck:hc,weight};render()});
document.querySelectorAll('.muwDel').forEach(el=>el.onclick=()=>{cfg.uplinks.splice(+el.dataset.i,1);render()});
document.querySelectorAll('.muwUp').forEach(el=>el.onclick=()=>{const i=+el.dataset.i;if(i<=0)return;const u=cfg.uplinks;[u[i-1],u[i]]=[u[i],u[i-1]];render()});
document.querySelectorAll('.muwDown').forEach(el=>el.onclick=()=>{const i=+el.dataset.i;const u=cfg.uplinks;if(i>=u.length-1)return;[u[i+1],u[i]]=[u[i],u[i+1]];render()});
const ap=$('#wanApply');if(ap)ap.onclick=async()=>{const mode=$('#muwMode').value;if(cfg.uplinks.length<2){$('#wanMsg').textContent='Treba barem dva uplinka.';return}if(!confirm('Primijeniti multi-WAN u načinu „'+(mode==='failover'?'Failover':'Load-balance')+'\"? Mijenja default rutu. MORAŠ potvrditi unutar 120 s inače se vraća staro (zaštita od gubitka pristupa).'))return;$('#wanMsg').textContent='Primjena…';try{await api('/api/multiwan/apply',{method:'POST',body:JSON.stringify({enabled:true,mode,uplinks:cfg.uplinks})});multiwanPage()}catch(err){$('#wanMsg').textContent=err.message}};
const off=$('#wanOff');if(off)off.onclick=async()=>{if(!confirm('Isključiti multi-WAN?'))return;try{await api('/api/multiwan/apply',{method:'POST',body:JSON.stringify({enabled:false,mode:$('#muwMode').value,uplinks:cfg.uplinks})});multiwanPage()}catch(err){alert(err.message)}};
if($('#wanConfirm'))$('#wanConfirm').onclick=async()=>{try{await api('/api/multiwan/confirm',{method:'POST',body:'{}'});multiwanPage()}catch(err){alert(err.message)}};
if($('#wanRollback'))$('#wanRollback').onclick=async()=>{try{await api('/api/multiwan/rollback',{method:'POST',body:'{}'});multiwanPage()}catch(err){alert(err.message)}}};
render();}
async function vpnPage(){const v=await api('/api/vpn');
const peers=(v.peers||[]).map(p=>`<tr><td>${escapeHtml(p.name)}</td><td>${escapeHtml(p.address)}</td><td>${p.fullTunnel?'puni tunel':'split'}</td><td>${p.expiresAt?new Date(p.expiresAt).toLocaleDateString():'—'}</td><td><button class="vpnDel" data-n="${escapeHtml(p.name)}">Ukloni</button></td></tr>`).join('');
$('#content').innerHTML=`<div class="panel"><h2>WireGuard VPN ${v.enabled?'<span class="badge">aktivan</span>':''}</h2>
${help('<b>VPN za rad s daljine</b> (pojedinačni korisnici, „road-warrior"). Korisnik instalira aplikaciju WireGuard i skenira <b>QR kod</b> koji dobiješ kad dodaš korisnika. <br><br><b>Kako radi po zadanom (split-tunnel):</b> kroz VPN putuje <b>samo promet prema tvojim internim mrežama</b> (LAN, serveri), a korisnikov <b>običan internet ostaje na njegovoj vezi</b> — brže je i privatnije, i ne opterećuje tvoju vezu. Polje <b>„Interne mreže kroz VPN"</b> su baš te mreže; ako ga ostaviš prazno, sam se upiše tvoj LAN. <br><br><b>Puni tunel</b> (baš SAV korisnikov promet ide kroz VPN) postoji, ali ga biraš svjesno pri dodavanju korisnika — u većini slučajeva NE treba. <br><br><b>Endpoint</b> je tvoja javna adresa i port na koje se korisnici spajaju — taj UDP port otvori u firewallu (Gateway). Privatni ključ korisnika se nigdje ne sprema. Za spajanje cijelih <b>lokacija</b> (ne pojedinaca) koristi Site-to-Site ili IPsec.')}
<form id="vpnForm" class="stack">
<label><input id="vEnabled" type="checkbox" ${v.enabled?'checked':''}> VPN uključen</label>
<label>VPN subnet <input id="vSubnet" value="${escapeHtml(v.subnet||'10.8.0.0/24')}"></label>
<label>Port <input id="vPort" type="number" value="${v.listenPort||51820}"></label>
<label>Endpoint (javna adresa:port) <input id="vEndpoint" value="${escapeHtml(v.endpoint||'')}" placeholder="vpn.example.com:51820"></label>
<label>DNS za klijente <input id="vDns" value="${escapeHtml(v.dns||'')}" placeholder="192.168.10.1"></label>
<label>Interne mreže kroz VPN (CIDR, zarezom) — prazno = tvoj LAN <input id="vSplit" value="${escapeHtml((v.splitNetworks||[]).join(', '))}" placeholder="npr. 192.168.10.0/24"></label>
<div><button type="submit">Spremi i primijeni</button></div><div id="vMsg" class="muted"></div></form>
<p class="muted">Napomena: otvorite UDP port ${v.listenPort||51820} u firewallu (Gateway modul) i po potrebi dodajte VPN subnet u dozvoljene mreže.</p></div>
<div class="panel"><h2>Peerovi (${(v.peers||[]).length})</h2><table><thead><tr><th>Korisnik</th><th>Adresa</th><th>Profil</th><th>Vrijedi do</th><th></th></tr></thead><tbody>${peers}</tbody></table>
<div class="wizRow"><button id="vpnWiz">Wizard: VPN korisnik (W7)</button></div></div>`;
$('#vpnForm').onsubmit=async e=>{e.preventDefault();$('#vMsg').textContent='Primjena…';try{await api('/api/vpn/apply',{method:'POST',body:JSON.stringify({enabled:$('#vEnabled').checked,subnet:$('#vSubnet').value.trim(),listenPort:parseInt($('#vPort').value,10)||51820,endpoint:$('#vEndpoint').value.trim(),dns:$('#vDns').value.trim(),splitNetworks:$('#vSplit').value.split(',').map(s=>s.trim()).filter(Boolean)})});vpnPage()}catch(err){$('#vMsg').textContent=err.message}};
$('#vpnWiz').onclick=()=>wizVPNUser().catch(e=>alert(e.message));
document.querySelectorAll('.vpnDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Ukloniti peer ${el.dataset.n}? Pristup prestaje odmah.`))return;try{await api(`/api/vpn/peers/${encodeURIComponent(el.dataset.n)}`,{method:'DELETE'});vpnPage()}catch(err){alert(err.message)}})}
async function openvpnPage(){const o=await api('/api/openvpn');const e=escapeHtml;
const aliases=((await api('/api/firewall').catch(()=>({aliases:[]}))).aliases)||[];
const validDate=d=>d&&new Date(d).getFullYear()>2000;
const OVSVC=[['','— odaberi servis —','',0],['rdp','Remote Desktop (RDP)','tcp',3389],['ssh','SSH','tcp',22],['https','HTTPS','tcp',443],['http','HTTP','tcp',80],['smb','Dijeljenje datoteka (SMB)','tcp',445],['vnc','VNC','tcp',5900],['dns','DNS','udp',53],['winrm','WinRM','tcp',5985],['all','Sve (bilo koji port)','any',0]];
const accSummary=a=>!a||!a.length?'<span class="muted">sve interno</span>':a.map(r=>e(r.destAlias||r.dest)+(r.port?':'+r.port:'')+(r.proto&&r.proto!=='any'?'/'+r.proto:'')).join(', ');
const clients=(o.clients||[]).map(c=>`<tr><td><b>${e(c.name)}</b></td><td class="muted small">${e(c.vpnAddr||'—')}</td><td class="small">${accSummary(c.access)}</td><td>${validDate(c.expiresAt)?new Date(c.expiresAt).toLocaleDateString('hr-HR'):'—'}</td><td class="rowacts"><button class="ovAcc ghost" data-n="${e(c.name)}">Pristup</button> <button class="ovDel danger" data-n="${e(c.name)}">Opozovi</button></td></tr>`).join('');
$('#content').innerHTML=`<div class="panel"><h2>OpenVPN ${o.enabled?'<span class="badge">aktivan</span>':''}</h2>
${help('<b>Ukratko:</b> VPN za rad s daljine preko aplikacije OpenVPN. Uključi server, dodaj korisnika i preuzmi njegov <b>.ovpn</b> profil — sve je u jednom fajlu (certifikat, ključ, tls-crypt). <br><br>Po zadanom je <b>split-tunnel</b>: kroz VPN putuje samo promet prema tvojim internim mrežama, a korisnikov <b>običan internet ostaje na njegovoj vezi</b>. Polje „Interne mreže" prazno = sam se upiše tvoj LAN. <br><br><b>Opoziv</b> korisnika djeluje odmah (CRL). <b>Endpoint</b> je tvoja javna adresa (bez porta) na koju se korisnici spajaju — UDP port se <b>sam otvori</b> u firewallu. Vlastiti CA i certifikati generiraju se automatski; privatni ključevi korisnika se nigdje ne spremaju.')}
<form id="ovForm" class="stack">
<label><input id="ovEn" type="checkbox" ${o.enabled?'checked':''}> OpenVPN uključen</label>
<label>VPN subnet <input id="ovSubnet" value="${e(o.subnet||'10.9.0.0/24')}"></label>
<label>Port (UDP) <input id="ovPort" type="number" value="${o.port||1194}"></label>
<label>Endpoint (javna adresa, bez porta) <input id="ovEndpoint" value="${e(o.endpoint||'')}" placeholder="vpn.example.com"></label>
<label>DNS za klijente <input id="ovDns" value="${e(o.dns||'')}" placeholder="10.10.10.1"></label>
<label>Interne mreže kroz VPN (CIDR, zarezom) — prazno = tvoj LAN <input id="ovSplit" value="${e((o.splitNetworks||[]).join(', '))}" placeholder="npr. 10.10.10.0/24"></label>
<div><button type="submit">Spremi i primijeni</button></div><div id="ovMsg" class="muted"></div></form></div>
<div class="panel"><h2>Korisnici (${(o.clients||[]).length})</h2><table><thead><tr><th>Korisnik</th><th>VPN IP</th><th>Smije na</th><th>Vrijedi do</th><th></th></tr></thead><tbody>${clients||'<tr><td colspan="5" class="muted">Nema korisnika.</td></tr>'}</tbody></table>
<div id="ovAccessBox"></div>
${o.provisioned?`<h3>Dodaj korisnika</h3><p class="muted small">Uz certifikat, korisnik se prijavljuje <b>imenom i lozinkom</b>. Lozinku ovdje postaviš i javiš korisniku; on je unese pri spajanju. „Vrijedi" je rok certifikata (0 = 2 godine).</p><div class="filterbar"><input id="ovcName" placeholder="ime (npr. ivan)"><input id="ovcPass" type="password" placeholder="lozinka (min 8)"><input id="ovcExp" type="number" placeholder="dana (0=2god)" style="max-width:120px"><button type="button" id="ovcAdd">Dodaj i preuzmi .ovpn</button></div><div id="ovcMsg" class="muted"></div>`:'<p class="muted">Uključi OpenVPN da bi mogao dodavati korisnike.</p>'}</div>`;
$('#ovForm').onsubmit=async ev=>{ev.preventDefault();$('#ovMsg').textContent='Primjena…';try{await api('/api/openvpn/apply',{method:'POST',body:JSON.stringify({enabled:$('#ovEn').checked,subnet:$('#ovSubnet').value.trim(),port:parseInt($('#ovPort').value,10)||1194,endpoint:$('#ovEndpoint').value.trim(),dns:$('#ovDns').value.trim(),splitNetworks:$('#ovSplit').value.split(',').map(s=>s.trim()).filter(Boolean)})});openvpnPage()}catch(err){$('#ovMsg').textContent=err.message}};
document.querySelectorAll('.ovDel').forEach(el=>el.onclick=async()=>{if(!confirm('Opozvati korisnika '+el.dataset.n+'? Profil odmah prestaje raditi.'))return;try{await api('/api/openvpn/clients/'+encodeURIComponent(el.dataset.n),{method:'DELETE'});openvpnPage()}catch(err){alert(err.message)}});
const ovcAdd=$('#ovcAdd');if(ovcAdd)ovcAdd.onclick=async()=>{const name=$('#ovcName').value.trim();const pass=$('#ovcPass').value;const exp=parseInt($('#ovcExp').value,10)||0;const m=$('#ovcMsg');if(!name){m.textContent='Upiši ime korisnika.';return}if((pass||'').length<8){m.textContent='Lozinka mora imati barem 8 znakova.';return}m.textContent='Generiram profil…';try{const res=await fetch('/api/openvpn/clients',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrfToken()},body:JSON.stringify({name,password:pass,expiryDays:exp})});if(!res.ok){const b=await res.json().catch(()=>({}));throw Error(b.error||'Greška')}const blob=await res.blob();const url=URL.createObjectURL(blob);const aTag=document.createElement('a');aTag.href=url;aTag.download=name+'.ovpn';aTag.click();URL.revokeObjectURL(url);m.textContent='Profil '+name+'.ovpn preuzet.';openvpnPage()}catch(err){m.textContent=err.message}};
const svcName=r=>{const m=OVSVC.find(s=>s[0]&&s[2]===r.proto&&s[3]===r.port);return m?m[1]:(r.proto==='any'?'Sve (bilo koji port)':'Prilagođeno');};
const openOVAccess=name=>{const c=(o.clients||[]).find(x=>x.name===name);if(!c)return;let rules=(c.access||[]).map(r=>({dest:r.dest,proto:r.proto||'any',port:r.port||0}));const box=$('#ovAccessBox');
const render=()=>{box.innerHTML=`<div class="panel"><h3>Pristup za korisnika: ${e(name)} <span class="muted small">(${e(c.vpnAddr||'')})</span></h3>
<p class="muted small">Prazno = korisnik smije na sve tvoje interne mreže. Dodaj pravila da ga ograničiš — <b>odredište</b> (IP ili mreža) + <b>servis</b> iz izbornika (npr. samo Remote Desktop na jedan server). „Sve" = bilo koji port na tom odredištu.</p>
<table class="compact"><thead><tr><th>Odredište</th><th>Servis</th><th>Proto/Port</th><th></th></tr></thead><tbody>${rules.length?rules.map((r,i)=>`<tr><td><b>${e(r.destAlias||r.dest)}</b>${r.destAlias?' <span class="badge">alias</span>':''}</td><td>${e(svcName(r))}</td><td class="muted">${r.proto==='any'?'sve':e(r.proto)+(r.port?':'+r.port:'')}</td><td class="rowacts"><button class="oaEdit ghost" data-i="${i}">Uredi</button> <button class="oaDel danger" data-i="${i}">Ukloni</button></td></tr>`).join(''):'<tr><td colspan="4" class="muted">Bez ograničenja — smije na sve interno.</td></tr>'}</tbody></table>
<div class="filterbar"><select id="oaAlias"><option value="">— IP/mreža ručno —</option>${aliases.map(a=>`<option value="${e(a.name)}">${e(a.name)} (${e((a.values||[]).join(', '))})</option>`).join('')}</select><input id="oaDest" placeholder="ili IP/mreža ručno"><select id="oaSvc">${OVSVC.map(s=>`<option value="${s[0]}">${e(s[1])}</option>`).join('')}</select><input id="oaPort" type="number" placeholder="ili custom port" style="max-width:130px"><button type="button" id="oaAdd" class="ghost">Dodaj pravilo</button></div>
<p class="muted small">Odaberi <b>alias</b> (imenovani server/mreža iz Firewall → Aliasi) ili upiši IP/mrežu ručno. Aliasi su transparentni kroz sustav — mijenjaš IP na jednom mjestu, pravila prate.</p>
<div class="btnrow"><button type="button" id="oaSave">Spremi pristup</button> <button type="button" id="oaClose" class="ghost">Zatvori</button></div><div id="oaMsg" class="muted"></div></div>`;
$('#oaAdd').onclick=()=>{const al=$('#oaAlias').value;const dest=$('#oaDest').value.trim();const sv=OVSVC.find(s=>s[0]===$('#oaSvc').value);let proto='any',port=0;if(sv&&sv[0]&&sv[0]!=='all'){proto=sv[2];port=sv[3];}const cp=parseInt($('#oaPort').value,10)||0;if(cp){port=cp;if(proto==='any')proto='tcp';}if(al){rules.push({destAlias:al,proto,port})}else{if(!isIPv4(dest)&&!isCIDR(dest)){$('#oaMsg').textContent='Odaberi alias ili upiši ispravan IP/CIDR.';return}rules.push({dest,proto,port})}$('#oaAlias').value='';$('#oaDest').value='';$('#oaPort').value='';render()};
box.querySelectorAll('.oaDel').forEach(el=>el.onclick=()=>{rules.splice(+el.dataset.i,1);render()});
box.querySelectorAll('.oaEdit').forEach(el=>el.onclick=()=>{const r=rules[+el.dataset.i];rules.splice(+el.dataset.i,1);render();if(r.destAlias){$('#oaAlias').value=r.destAlias}else{$('#oaDest').value=r.dest||''}const sv=OVSVC.find(s=>s[0]&&s[2]===(r.proto||'any')&&s[3]===(r.port||0));if(sv){$('#oaSvc').value=sv[0]}else{$('#oaSvc').value='all';$('#oaPort').value=r.port||''}$('#oaMsg').textContent='Uređuješ pravilo — prilagodi pa klikni „Dodaj pravilo".'});
$('#oaSave').onclick=async()=>{$('#oaMsg').textContent='Spremam…';try{await api('/api/openvpn/clients/'+encodeURIComponent(name)+'/access',{method:'PUT',body:JSON.stringify({rules})});openvpnPage()}catch(err){$('#oaMsg').textContent=err.message}};
$('#oaClose').onclick=()=>{box.innerHTML=''};};
render();box.scrollIntoView({behavior:'smooth'});};
document.querySelectorAll('.ovAcc').forEach(b=>b.onclick=()=>openOVAccess(b.dataset.n));}
async function wizVPNUser(){
runWizard('Čarobnjak: VPN korisnik (W7)',[
{title:'Korisnik',render:s=>`<label>Ime korisnika/uređaja <input id="v1name" value="${escapeHtml(s.name||'')}" placeholder="ana-laptop"></label>`,collect:s=>{s.name=$('#v1name').value.trim().toLowerCase();return s.name?null:'Unesite ime.'}},
{title:'Profil tunela',render:s=>`<label>Profil tunela <select id="v2prof"><option value="split" ${s.prof!=='full'?'selected':''}>Split (preporučeno) — kroz VPN samo interne mreže, internet ostaje na korisniku</option><option value="full" ${s.prof==='full'?'selected':''}>Puni tunel — SAV korisnikov promet kroz VPN (rijetko; sporije, sve ide preko tebe)</option></select></label><p class="muted small">Split je zadano i gotovo uvijek pravi izbor — korisnik radi na tvojim resursima preko VPN-a, a svoj internet vozi svojom vezom.</p><label>Rok valjanosti (dana, 0 = bez roka) <input id="v2exp" type="number" value="${s.exp||0}" min="0"></label>`,collect:s=>{s.prof=$('#v2prof').value;s.exp=parseInt($('#v2exp').value,10)||0;return null}},
{title:'Pregled',render:s=>`<p>Korisnik: <b>${escapeHtml(s.name)}</b><br>Profil: <b>${s.prof==='full'?'puni tunel':'split'}</b><br>Rok: <b>${s.exp?s.exp+' dana':'bez roka'}</b></p><p class="muted">Privatni ključ klijenta generira se sada i prikazuje samo jednom — ne pohranjuje se na appliance.</p>`}],
async s=>{const r=await api('/api/vpn/peers',{method:'POST',body:JSON.stringify({name:s.name,fullTunnel:s.prof==='full',expireDays:s.exp})});showVPNConf(r);openModule('vpn')})}
function showVPNConf(r){const ov=document.createElement('div');ov.className='overlay';ov.innerHTML=`<div class="modal"><h2>VPN konfiguracija — ${escapeHtml(r.peer.name)}</h2><p class="error">Prikazuje se samo jednom. Preuzmite .conf ili skenirajte QR odmah.</p>${r.qrPng?`<p style="text-align:center"><img alt="QR" style="max-width:320px;background:#fff;padding:8px;border-radius:8px" src="data:image/png;base64,${r.qrPng}"></p>`:''}<pre class="muted" style="white-space:pre-wrap">${escapeHtml(r.clientConf)}</pre><div class="wizNav"><button id="vpnDl">Preuzmi .conf</button><button id="vpnClose" class="ghost">Zatvori</button></div></div>`;document.body.appendChild(ov);
$('#vpnDl').onclick=()=>{const b=new Blob([r.clientConf],{type:'text/plain'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=`${r.peer.name}.conf`;a.click();URL.revokeObjectURL(a.href)};
$('#vpnClose').onclick=()=>ov.remove()}
async function certsPage(){const certs=await api('/api/certs');
const rows=certs.map(c=>`<tr><td>${escapeHtml(c.name)} ${c.public?'<span class="badge">Let’s Encrypt</span>':''}</td><td>${escapeHtml((c.sans||[]).join(', '))}</td><td>${c.issuedAt?new Date(c.issuedAt).toLocaleDateString():''}</td><td>${c.notAfter?new Date(c.notAfter).toLocaleDateString():'—'}</td><td><button class="crtGui" data-n="${escapeHtml(c.name)}">Deploy na GUI</button> <button class="crtDel" data-n="${escapeHtml(c.name)}">Obriši</button></td></tr>`).join('');
$('#content').innerHTML=`<div class="panel"><h2>Certifikati (${certs.length})</h2>
${help('<b>Interni CA (step-ca)</b> izdaje certifikate za LAN uređaje i sam GUI bez javne domene — dodaj SAN-ove (nazivi/IP-ovi) i po želji postavi kao GUI certifikat. <b>Javni ACME (Let’s Encrypt)</b> je za servise s pravom domenom izložene internetu: domena mora pokazivati na naš WAN (ili DNAT na nas), validacija <b>HTTP-01</b> privremeno otvori port 80, ili <b>DNS-01</b> preko naše PowerDNS (podržava <b>wildcard *.example.com</b>; zona mora biti autoritativna kod nas). Obnova je automatska preko certbot.timer. Za IPsec cert-auth iskoristi ovdje izdani cert ili unesi tuđi.')}<table><thead><tr><th>Ime</th><th>SAN-ovi</th><th>Izdan</th><th>Istječe</th><th></th></tr></thead><tbody>${rows}</tbody></table>
<div class="wizRow"><button id="crtWiz">Wizard: novi certifikat (W6)</button></div>
<p class="muted">Interni certifikati iz Step CA (rok 90 dana, automatska obnova dnevnim timerom). Javni (Let's Encrypt) preko HTTP-01, obnova preko certbot.timer. Za objavljene servise odaberite TLS izvor "managed" s imenom certifikata.</p>
<div id="crtMsg" class="muted"></div></div>`;
$('#crtWiz').onclick=()=>wizCert().catch(e=>alert(e.message));
document.querySelectorAll('.crtGui').forEach(el=>el.onclick=async()=>{if(!confirm(`Postaviti ${el.dataset.n} kao GUI certifikat?`))return;try{await api(`/api/certs/${encodeURIComponent(el.dataset.n)}/deploy-gui`,{method:'POST',body:'{}'});$('#crtMsg').textContent='Certifikat postavljen — nginx ponovno učitan.'}catch(err){alert(err.message)}});
document.querySelectorAll('.crtDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati certifikat ${el.dataset.n}?`))return;try{await api(`/api/certs/${encodeURIComponent(el.dataset.n)}`,{method:'DELETE'});certsPage()}catch(err){alert(err.message)}})}
async function wizCert(){
runWizard('Čarobnjak: Certifikat (W6)',[
{title:'Tip certifikata',render:s=>`<label>Tip <select id="c1type"><option value="internal" ${s.type!=='public'?'selected':''}>Interni (Step CA) — za LAN</option><option value="public" ${s.type==='public'?'selected':''}>Javni (Let's Encrypt) — za internet</option></select></label><p class="muted">Interni: privatna imena/IP-ovi bez javne domene. Javni: prava domena koja pokazuje na WAN (ili DNAT na nas); validacija HTTP-01 privremeno otvara port 80.</p>`,collect:s=>{s.type=$('#c1type').value;return null}},
{title:'Podaci',render:s=>s.type==='public'?`<label>Ime certifikata <input id="c2name" value="${escapeHtml(s.name||'')}" placeholder="wiki"></label><label>Javna domena (FQDN; DNS-01 dopušta wildcard *.example.com) <input id="c2dom" value="${escapeHtml(s.domain||'')}" placeholder="wiki.example.com"></label><label>Kontakt e-mail (ACME) <input id="c2mail" value="${escapeHtml(s.email||'')}" placeholder="admin@example.com"></label><label>Validacija <select id="c2chal"><option value="http-01" ${s.challenge==='dns-01'?'':'selected'}>HTTP-01 (privremeno otvara port 80; bez wildcard-a)</option><option value="dns-01" ${s.challenge==='dns-01'?'selected':''}>DNS-01 (preko naše PowerDNS; podržava wildcard)</option></select></label><p class="muted">HTTP-01: domena javno dostupna na portu 80 tijekom izdavanja. DNS-01: naša PowerDNS mora biti autoritativna za zonu (javni NS pokazuje na nas) — podržava <code>*.example.com</code>. Obnova je automatska (certbot.timer).</p>`:`<label>Ime certifikata <input id="c2name" value="${escapeHtml(s.name||'')}" placeholder="wiki"></label><label>SAN-ovi (zarezom: imena i/ili IP) <input id="c2sans" value="${escapeHtml(s.sans||'')}" placeholder="wiki.example.internal, 192.168.10.5"></label>`,collect:s=>{s.name=$('#c2name').value.trim().toLowerCase();if(s.type==='public'){s.domain=$('#c2dom').value.trim().toLowerCase();s.email=$('#c2mail').value.trim();s.challenge=$('#c2chal').value;if(s.domain.startsWith('*.')&&s.challenge!=='dns-01')return'Wildcard domena zahtijeva DNS-01 validaciju.';return(s.name&&s.domain&&s.email)?null:'Unesite ime, domenu i e-mail.'}s.sans=$('#c2sans').value.trim();return(s.name&&s.sans)?null:'Unesite ime i barem jedan SAN.'}},
{title:'Deploy cilj',render:s=>`<label><input id="c3gui" type="checkbox" ${s.gui?'checked':''}> Postavi kao GUI certifikat (zamjenjuje bootstrap)</label><p class="muted">Za objavljene servise: nakon izdavanja odaberite TLS "managed" + ime certifikata u Reverse Proxy modulu.</p>`,collect:s=>{s.gui=$('#c3gui').checked;return null}},
{title:'Pregled i izdavanje',render:s=>`<p>Tip: <b>${s.type==='public'?'Javni (Let\'s Encrypt)':'Interni'}</b><br>Ime: <b>${escapeHtml(s.name)}</b><br>${s.type==='public'?'Domena: <b>'+escapeHtml(s.domain)+'</b> · Validacija: <b>'+escapeHtml(s.challenge||'http-01')+'</b>':'SAN-ovi: <b>'+escapeHtml(s.sans)+'</b>'}<br>Deploy: <b>${s.gui?'GUI vhost':'samo izdaj'}</b></p>${s.type==='public'&&(s.challenge==='dns-01')?'<p class="muted">DNS-01 objavljuje privremeni TXT zapis u lokalnoj PowerDNS zoni i briše ga nakon validacije.</p>':''}`}],
async s=>{const body=s.type==='public'?{type:'public',name:s.name,domain:s.domain,email:s.email,challenge:s.challenge||'http-01',deployGui:s.gui}:{type:'internal',name:s.name,sans:s.sans.split(',').map(x=>x.trim()).filter(Boolean),deployGui:s.gui};const r=await api('/api/certs/issue',{method:'POST',body:JSON.stringify(body)});if(r.note)alert(r.note);openModule('certificates')})}
async function proxyPage(){const apps=await api('/api/proxy');
const rows=apps.map((x,i)=>`<tr><td>${escapeHtml(x.name)}</td><td>${escapeHtml(x.hostname)}</td><td>${escapeHtml(x.upstreamIp)}:${x.upstreamPort}</td><td>${escapeHtml(x.tls)}</td><td>${escapeHtml((x.allowCidrs||[]).join(', ')||'svi')}</td><td><button class="pxDel" data-i="${i}">Ukloni</button></td></tr>`).join('');
$('#content').innerHTML=`<div class="panel"><h2>Objavljeni servisi (${apps.length})</h2>
${help('Reverse proxy (nginx) objavljuje interni servis na HTTPS-u: upiši vanjski naziv (host), interni cilj (IP:port) i TLS certifikat (iz modula Certifikati). Podržava WebSocket. Prije primjene radi se <code>nginx -t</code> pa rollback na grešku. Za izlaganje internetu kombiniraj s <b>NAT/port forward</b> na Gateway-u.')}<table><thead><tr><th>Servis</th><th>Hostname</th><th>Upstream</th><th>TLS</th><th>Pristup</th><th></th></tr></thead><tbody>${rows}</tbody></table>
<div class="wizRow"><button id="pxWiz">Wizard: objavi servis (W5)</button></div>
<p class="muted">Promjene se primjenjuju transakcijski: nginx -t validacija s automatskim vraćanjem stare konfiguracije. Upstream se prije objave provjerava TCP probom.</p>
<div id="pxMsg" class="muted"></div></div>`;
$('#pxWiz').onclick=()=>wizPublish(apps).catch(e=>alert(e.message));
document.querySelectorAll('.pxDel').forEach(el=>el.onclick=async()=>{const i=parseInt(el.dataset.i,10);if(!confirm(`Ukloniti servis ${apps[i].name}?`))return;const next=apps.filter((_,j)=>j!==i);try{await api('/api/proxy/apply',{method:'POST',body:JSON.stringify({apps:next,force:true})});proxyPage()}catch(err){alert(err.message)}})}
async function wizPublish(existing){
runWizard('Čarobnjak: Publish service (W5)',[
{title:'Servis i upstream',render:s=>`<label>Ime servisa <input id="p1name" value="${escapeHtml(s.name||'')}" placeholder="wiki"></label><label>Upstream IP <input id="p1ip" value="${escapeHtml(s.ip||'')}" placeholder="192.168.10.5"></label><label>Upstream port <input id="p1port" type="number" value="${s.port||80}" min="1" max="65535"></label><label><input id="p1ws" type="checkbox" ${s.ws?'checked':''}> WebSocket podrška</label>`,collect:s=>{s.name=$('#p1name').value.trim();s.ip=$('#p1ip').value.trim();s.port=parseInt($('#p1port').value,10);s.ws=$('#p1ws').checked;return(s.name&&s.ip&&s.port)?null:'Ispunite ime, IP i port.'}},
{title:'Hostname i TLS',render:s=>`<label>Javni hostname <input id="p2host" value="${escapeHtml(s.host||'')}" placeholder="wiki.example.internal"></label><label>TLS izvor <select id="p2tls"><option value="appliance" ${s.tls==='appliance'?'selected':''}>Appliance certifikat (bootstrap/step-ca)</option><option value="managed" ${s.tls==='managed'?'selected':''}>Upravljani certifikat (W6 modul)</option><option value="custom" ${s.tls==='custom'?'selected':''}>Vlastiti certifikat (putanje)</option><option value="none" ${s.tls==='none'?'selected':''}>Bez TLS-a (HTTP 80)</option></select></label><label>Ime certifikata (managed) <input id="p2cname" value="${escapeHtml(s.cname||'')}" placeholder="wiki"></label><label>Cert putanja (custom) <input id="p2cert" value="${escapeHtml(s.cert||'')}" placeholder="/etc/ssl/certs/wiki.crt"></label><label>Key putanja (custom) <input id="p2key" value="${escapeHtml(s.key||'')}" placeholder="/etc/ssl/private/wiki.key"></label>`,collect:s=>{s.host=$('#p2host').value.trim().toLowerCase();s.tls=$('#p2tls').value;s.cname=$('#p2cname').value.trim().toLowerCase();s.cert=$('#p2cert').value.trim();s.key=$('#p2key').value.trim();if(!s.host)return'Unesite hostname.';if(s.tls==='custom'&&(!s.cert||!s.key))return'Custom TLS traži putanje certifikata i ključa.';if(s.tls==='managed'&&!s.cname)return'Managed TLS traži ime certifikata (W6).';return null}},
{title:'Pristup i DNS',render:s=>`<label>Dozvoljene mreže (CIDR, zarezom; prazno = svi) <input id="p3acl" value="${escapeHtml(s.acl||'')}" placeholder="192.168.10.0/24"></label><label><input id="p3dns" type="checkbox" ${s.dns!==false?'checked':''}> Kreiraj DNS A zapis za hostname</label><label>IP za DNS zapis (adresa appliancea) <input id="p3dnsip" value="${escapeHtml(s.dnsIp||'')}" placeholder="192.168.10.1"></label>`,collect:s=>{s.acl=$('#p3acl').value.trim();s.dns=$('#p3dns').checked;s.dnsIp=$('#p3dnsip').value.trim();if(s.dns&&!s.dnsIp)return'Za DNS zapis unesite IP appliancea.';return null}},
{title:'Pregled i objava',render:s=>`<p>Servis: <b>${escapeHtml(s.name)}</b> → <b>${escapeHtml(s.ip)}:${s.port}</b>${s.ws?' (WS)':''}<br>Hostname: <b>${escapeHtml(s.host)}</b> · TLS: <b>${escapeHtml(s.tls)}</b><br>Pristup: <b>${escapeHtml(s.acl||'svi')}</b> · DNS zapis: <b>${s.dns?'da → '+escapeHtml(s.dnsIp):'ne'}</b></p><p class="muted">Objava provjerava dostupnost upstreama (TCP) i prolazi nginx -t validaciju s automatskim revertom.</p>`}],
async s=>{const app={name:s.name,hostname:s.host,upstreamIp:s.ip,upstreamPort:s.port,tls:s.tls,certPath:s.tls==='custom'?s.cert:'',keyPath:s.tls==='custom'?s.key:'',certName:s.tls==='managed'?s.cname:'',allowCidrs:s.acl?s.acl.split(',').map(x=>x.trim()).filter(Boolean):[],webSocket:s.ws};
try{await api('/api/proxy/apply',{method:'POST',body:JSON.stringify({apps:[...existing,app],force:false})})}catch(err){if(err.message.includes('force=true')&&confirm(err.message+'\n\nObjaviti svejedno?')){await api('/api/proxy/apply',{method:'POST',body:JSON.stringify({apps:[...existing,app],force:true})})}else{throw err}}
if(s.dns){const zone=s.host.split('.').slice(1).join('.');try{await api(`/api/dns/zones/${encodeURIComponent(zone)}/records`,{method:'PUT',body:JSON.stringify({name:s.host,type:'A',ttl:3600,contents:[s.dnsIp],delete:false})})}catch(err){alert('Servis je objavljen, ali DNS zapis nije kreiran: '+err.message)}}
openModule('proxy')})}
async function rpzPage(){const c=await api('/api/rpz');
$('#content').innerHTML=`<div class="panel"><h2>RPZ DNS filtering</h2>
${help('<b>Ukratko:</b> ovdje blokiraš neželjene i opasne web-stranice <b>po nazivu domene</b> — kad ih netko na mreži pokuša otvoriti, uređaj ne dobije adresu i stranica se jednostavno ne učita. Vrijedi za <b>sve</b> uređaje koji ovu kutiju koriste kao DNS, i radi i na slabom hardveru. <br><br>Uključi gotove liste ili dodaj vlastite domene (blokira se i sve poddomene). <br><br><i>Tehnički:</i> RPZ (DNS sinkhole) u Unboundu vraća NXDOMAIN za domene s liste; svaki pogodak se zapiše kao događaj. Za analizu <b>sadržaja</b> prometa (ne samo naziva domene) koristi <b>IDS/IPS</b>.')}<p class="muted">Blokirane domene (i njihove poddomene) vraćaju NXDOMAIN kroz Unbound. Ovo je security razina koja radi na svakom hardveru — bez Suricate. Svaki pogodak se logira kao dns-filter event.</p>
<form id="rpzForm" class="stack"><label><input id="rpzEnabled" type="checkbox" ${c.enabled?'checked':''}> Filtriranje uključeno</label>
<label>Blokirane domene (jedna po retku) <textarea id="rpzDomains" rows="8" placeholder="ads.example.com&#10;tracker.example.net">${escapeHtml((c.domains||[]).join('\n'))}</textarea></label>
<label>Vanjski RPZ feedovi (URL, jedan po retku) <textarea id="rpzFeeds" rows="3" placeholder="https://example.org/blocklist.rpz">${escapeHtml((c.feeds||[]).join('\n'))}</textarea></label>
<div><button type="submit">Primijeni</button></div><div id="rpzMsg" class="muted"></div></form>
<p class="muted">Provjera: <code>dig blokirana-domena @adresa-appliancea</code> mora vratiti NXDOMAIN, a event se pojavljuje u Monitoringu.</p></div>`;
$('#rpzForm').onsubmit=async e=>{e.preventDefault();$('#rpzMsg').textContent='Primjena…';const body={enabled:$('#rpzEnabled').checked,domains:$('#rpzDomains').value.split('\n').map(s=>s.trim()).filter(Boolean),feeds:$('#rpzFeeds').value.split('\n').map(s=>s.trim()).filter(Boolean)};try{await api('/api/rpz/apply',{method:'POST',body:JSON.stringify(body)});$('#rpzMsg').textContent=body.enabled?'RPZ primijenjen — Unbound ponovno učitan.':'RPZ isključen.'}catch(err){$('#rpzMsg').textContent=err.message}}}
async function idsPage(){const d=await api('/api/ids');let nics=[];try{nics=(await api('/api/gateway')).nics||[]}catch(e){}
const c=d.config||{};const sev=['security','critical','error','warning','notice','info'];
const stats=`<table><thead><tr><th>Razina</th><th>Broj (14 dana)</th></tr></thead><tbody>${sev.map(s=>`<tr><td>${s}</td><td>${d.stats14d[s]||0}</td></tr>`).join('')}</tbody></table>`;
const hwBadge=d.hw.ok?`<p class="muted">Hardver: ${d.hw.memMB} MB RAM, ${d.hw.cores} jezgri — ✓ zadovoljava uvjete security modula.</p>`:`<p class="error">${escapeHtml(d.hw.reason)}</p>`;
const modeInfo=c.mode==='off'?'<b>isključen</b>':`<b>${escapeHtml(c.mode.toUpperCase())}</b> na ${escapeHtml(c.interface||'—')} (IDS od ${c.idsEnabledAt?new Date(c.idsEnabledAt).toLocaleString():'—'})`;
$('#content').innerHTML=`<div class="panel"><h2>Suricata status</h2>
${help('<b>Ukratko:</b> automatski nadzor prometa koji prepoznaje napade i sumnjivo ponašanje. <b>IDS</b> ih samo <b>prijavi</b> (upozorenje u logu), a <b>IPS</b> ih i <b>aktivno blokira</b> u letu. <br><br>Motor je Suricata s bazom prepoznavanja koju treba <b>redovito ažurirati</b>. IPS ima sigurnosnu kočnicu: ako se Suricata zaustavi, promet i dalje prolazi (neće slučajno prekinuti mrežu). <br><br>Treba <b>Gateway mod</b>. Na slabijem hardveru radije koristi samo <b>IDS + DNS filtering</b> (lakše za procesor). <br><i>Tehnički:</i> promet ide kroz Suricatu preko nftables NFQUEUE.')}<p>Način rada: ${modeInfo}</p>${hwBadge}
<div class="wizRow"><button id="idsOn" ${d.hw.ok?'':'disabled'}>Uključi IDS</button> <button id="ipsWiz" ${d.hw.ok?'':'disabled'}>IPS wizard (W9)</button> <button id="idsOff" style="background:#e05d5d">Emergency IPS off</button></div>
<div id="idsMsg" class="muted"></div></div>
<div class="panel"><h2>IDS statistika (14 dana)</h2>${stats}<p class="muted">Alarmi iz eve.json ulaze u events tablicu (modul ids); security razina ide i na mail.</p></div>`;
$('#idsOn').onclick=()=>{const opts=nics.map(n=>n.name);const iface=prompt('Interface za nadzor (WAN):',c.interface||opts[0]||'');if(!iface)return;const home=prompt('HOME_NET (CIDR, prazno = RFC1918):',c.homeNet||'');api('/api/ids/enable',{method:'POST',body:JSON.stringify({mode:'ids',interface:iface.trim(),homeNet:(home||'').trim(),force:false})}).then(()=>idsPage()).catch(e=>{$('#idsMsg').textContent=e.message})};
$('#ipsWiz').onclick=()=>wizIPS(d,nics).catch(e=>alert(e.message));
$('#idsOff').onclick=async()=>{if(!confirm('Isključiti Suricatu (IDS/IPS)? Promet nastavlja teći bez inspekcije.'))return;try{await api('/api/ids/disable',{method:'POST',body:'{}'});idsPage()}catch(e){alert(e.message)}}}
async function wizIPS(d,nics){const c=d.config||{};
runWizard('Čarobnjak: IPS enablement (W9)',[
{title:'IDS statistika',render:s=>`<p>IDS način: <b>${escapeHtml(c.mode)}</b>${c.idsEnabledAt?` od ${new Date(c.idsEnabledAt).toLocaleString()}`:''}</p><table><thead><tr><th>Razina</th><th>14 dana</th></tr></thead><tbody>${['security','warning','notice'].map(x=>`<tr><td>${x}</td><td>${d.stats14d[x]||0}</td></tr>`).join('')}</tbody></table>${d.ips.allowed?'<p class="muted">Uvjet promatranja je zadovoljen.</p>':`<p class="error">${escapeHtml(d.ips.reason)}</p><label><input id="wIpsForce" type="checkbox"> Svjesno preskačem period promatranja (force)</label>`}`,collect:s=>{s.force=!d.ips.allowed&&$('#wIpsForce')?$('#wIpsForce').checked:false;if(!d.ips.allowed&&!s.force)return d.ips.reason;return null}},
{title:'Zona inspekcije',render:s=>`<p>Prva iteracija štiti samo promet <b>WAN → objavljeni servisi</b> (forward lanac). IPS radi kroz NFQUEUE 0 s <code>bypass</code> — pad Suricate ne ruši promet (fail-open).</p><p>Interface: <b>${escapeHtml(c.interface||'—')}</b> (iz IDS konfiguracije)</p>`},
{title:'Drop policy i primjena',render:s=>`<p class="error">IPS će aktivno blokirati promet koji pravila ocijene zlonamjernim. Gumb "Emergency IPS off" ostaje uvijek dostupan.</p><p>Primjena: Suricata prelazi u NFQUEUE način + nftables queue pravilo kroz 120 s confirm-or-rollback transakciju (potvrda na Gateway stranici).</p>`}],
async s=>{const r=await api('/api/ids/enable',{method:'POST',body:JSON.stringify({mode:'ips',interface:c.interface||'',homeNet:c.homeNet||'',force:!!s.force})});if(r.note)alert(r.note);openModule('ids')})}
async function interfacesPage(){const nics=await api('/api/interfaces');
const statusCell=n=>n.carrier?`<span class="status st-healthy">Spojen${n.speedMb?' · '+n.speedMb+' Mbps':''}</span>`:`<span class="status st-muted">Nije spojen</span>`;
const roleBadge=n=>n.role?`<span class="badge">${escapeHtml(n.role)}</span>`:'';
const ew=escapeHtml;
$('#content').innerHTML=`<div class="panel"><h2>Mrežni portovi (${nics.length})</h2>
<p class="muted">Svaki port ima <b>logički naziv</b> (npr. <code>wan1</code>, <code>lan0</code>) koji Saguaro drži stabilnim, a u stupcu <b>Hardver</b> je fizički naziv (<code>enpXsY</code> + PCI) za orijentaciju na kućištu. Dodaj <b>alias</b> (npr. „Ured WAN") pa se prikazuje kroz cijeli sustav. Ne znaš koji je port? Klikni <b>Identificiraj</b> — LED zatreperi ~10 s.</p>
<table><thead><tr><th>Port</th><th>Status / brzina</th><th>IP adresa</th><th>Hardver</th><th>Alias</th><th></th></tr></thead><tbody>${nics.map(n=>`<tr>
<td><div class="ifname"><span class="nav-ico">${ICONS.interfaces}</span><b>${ew(n.label||n.name)}</b> ${roleBadge(n)}</div>${n.label?`<div class="muted small">${ew(n.name)}</div>`:''}</td>
<td>${statusCell(n)}${n.state?`<div class="muted small">${ew(n.state)}</div>`:''}</td>
<td>${(n.addresses||[]).length?(n.addresses).map(a=>`<div>${ew(a)}</div>`).join(''):'<span class="muted">—</span>'}</td>
<td class="muted small">${n.sysName&&n.sysName!==n.name?ew(n.sysName)+'<br>':''}${n.bus?ew(n.bus)+'<br>':''}${n.driver?ew(n.driver):''}${n.mac?'<br>'+ew(n.mac):''}</td>
<td><input class="nicLbl" data-n="${ew(n.name)}" value="${ew(n.label||'')}" placeholder="npr. Ured WAN" style="max-width:150px;padding:6px 8px"></td>
<td class="rowacts"><button class="nicSave ghost" data-n="${ew(n.name)}">Spremi</button> <button class="nicId" data-n="${ew(n.name)}">Identificiraj</button></td></tr>`).join('')}</tbody></table>
<div id="nicMsg" class="muted"></div></div>`;
document.querySelectorAll('.nicSave').forEach(el=>el.onclick=async()=>{$('#nicMsg').textContent='';const inp=document.querySelector('.nicLbl[data-n="'+el.dataset.n+'"]');try{await api(`/api/interfaces/${encodeURIComponent(el.dataset.n)}/label`,{method:'PUT',body:JSON.stringify({label:inp.value.trim()})});await loadNicLabels();renderNav();$('#nicMsg').textContent=`Naziv za ${el.dataset.n} spremljen — vidljiv kroz sve menije.`}catch(e){$('#nicMsg').textContent=e.message}});
document.querySelectorAll('.nicId').forEach(el=>el.onclick=async()=>{$('#nicMsg').textContent='';try{const r=await api(`/api/interfaces/${encodeURIComponent(el.dataset.n)}/identify`,{method:'POST',body:JSON.stringify({seconds:10})});$('#nicMsg').textContent=`${el.dataset.n}: LED treperi ~${r.seconds}s — pogledaj koji port svijetli.`}catch(e){$('#nicMsg').textContent=e.message}})}
function isIPv4(s){return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s)}
// cidrNetwork turns a host CIDR like "10.10.10.1/24" into its network address
// "10.10.10.0/24", used to prefill the client/LAN network from a port's own IP.
function cidrNetwork(a){const m=/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(a||'');if(!m)return '';const b=+m[5];if(b<0||b>32)return '';const ip=((+m[1]<<24)|(+m[2]<<16)|(+m[3]<<8)|(+m[4]))>>>0;const mask=b===0?0:(0xffffffff<<(32-b))>>>0;const net=(ip&mask)>>>0;return `${net>>>24&255}.${net>>>16&255}.${net>>>8&255}.${net&255}/${b}`}
function isCIDR(s){const m=/^(.+)\/(\d{1,2})$/.exec(s);if(!m)return false;return isIPv4(m[1])&&+m[2]>=0&&+m[2]<=32}
async function routingPage(){const cfg=await api('/api/routes');const routes=cfg.routes||[];let nics=[];try{nics=await api('/api/interfaces')}catch(e){}
const save=list=>api('/api/routes',{method:'PUT',body:JSON.stringify({routes:list})});
const nicOpts=nics.map(n=>`<option value="${escapeHtml(n.name)}">`).join('');
$('#content').innerHTML=`<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h2 style="margin:0">Statičke rute (${routes.length})</h2><button type="button" id="rtNew">+ Dodaj rutu</button></div>
<p class="muted">Usmjeri promet za određenu mrežu kroz zadani gateway — npr. odredište <code>10.20.0.0/16</code> preko <code>192.168.50.254</code>. Rute su trajne (vraćaju se nakon reboota). Za default rutu koristi odredište <code>default</code>.</p>
${help('<b>Odredište</b> je mreža do koje želiš doći, u CIDR obliku (npr. <code>10.20.0.0/16</code> = cijela 10.20.x.x mreža). <b>Gateway</b> je IP susjednog rutera preko kojeg se do te mreže dolazi — mora biti u tvojoj lokalnoj mreži (on-link). <b>Sučelje</b> ostavi prazno osim ako moraš forsirati izlaz kroz točno određeni NIC. <b>Metrika</b> je prioritet (manji broj = veći prioritet) kad postoji više ruta do istog odredišta. Primjer: dvije lokacije spojene preko rutera 192.168.50.254 — dodaj <code>10.20.0.0/16 → 192.168.50.254</code>.')}
<table><thead><tr><th>Odredište</th><th>Gateway</th><th>Sučelje</th><th>Metrika</th><th></th></tr></thead><tbody>
${routes.length?routes.map((r,i)=>`<tr><td><b>${escapeHtml(r.destination)}</b></td><td>${escapeHtml(r.gateway)}</td><td class="muted">${escapeHtml(r.interface||'auto')}</td><td class="muted">${r.metric||0}</td><td><button class="rtDel danger" data-i="${i}">Obriši</button></td></tr>`).join(''):'<tr><td colspan="5" class="muted">Nema statičkih ruta.</td></tr>'}
</tbody></table>
<form id="rtAdd" class="stack" style="${drawerStyle}"><h4 id="rtFormTitle" style="margin:.1rem 0 .3rem">Nova ruta</h4>
<label>Odredište (CIDR ili "default") <input id="rtDest" placeholder="10.20.0.0/16" required></label>
<label>Gateway (IPv4) <input id="rtGw" placeholder="192.168.50.254" required></label>
<label>Sučelje (opcionalno) <input id="rtIf" list="rtNics" placeholder="auto"><datalist id="rtNics">${nicOpts}</datalist></label>
<label>Metrika <input id="rtMetric" type="number" min="0" value="0"></label>
<div class="btnrow"><button type="submit">Dodaj rutu</button> <button type="button" id="rtCancel" class="ghost">Odustani</button></div>
<div id="rtMsg" class="muted"></div></form></div>`;
document.querySelectorAll('.rtDel').forEach(el=>el.onclick=async()=>{$('#rtMsg')&&($('#rtMsg').textContent='');const list=routes.filter((_,j)=>j!==parseInt(el.dataset.i,10));try{await save(list);routingPage()}catch(e){alert(e.message)}});
makeDrawer({form:'rtAdd',title:'rtFormTitle',newBtn:'rtNew',cancel:'rtCancel',addTitle:'Nova ruta',reset:()=>{$('#rtAdd').reset();$('#rtMsg').textContent=''},focus:'rtDest'});
$('#rtAdd').onsubmit=async e=>{e.preventDefault();const msg=$('#rtMsg');msg.textContent='';const dest=$('#rtDest').value.trim(),gw=$('#rtGw').value.trim(),iface=$('#rtIf').value.trim(),metric=parseInt($('#rtMetric').value,10)||0;
if(dest!=='default'&&!isCIDR(dest)){msg.textContent='Odredište mora biti CIDR (npr. 10.20.0.0/16) ili "default".';return}
if(!isIPv4(gw)){msg.textContent='Gateway mora biti ispravna IPv4 adresa.';return}
if(metric<0){msg.textContent='Metrika ne može biti negativna.';return}
if(routes.some(r=>r.destination===dest)){msg.textContent='Ruta za to odredište već postoji.';return}
const list=routes.concat([{destination:dest,gateway:gw,interface:iface,metric:metric}]);
msg.textContent='Primjena…';try{await save(list);routingPage()}catch(err){msg.textContent=err.message}}}
async function systemPage(){const s=await api('/api/system');const p=s.profile;
$('#content').innerHTML=`<div class="panel"><h2>Način rada uređaja</h2>
<p class="muted">Odredi kako Saguaro radi u tvojoj mreži. Postavku možeš promijeniti kasnije — u <b>Router</b> modu UTM moduli (Gateway, IDS/IPS, VPN, Multi-WAN) su skriveni.</p>
<form id="spForm" class="stack">
<label class="radio"><input type="radio" name="prof" value="gateway" ${p==='gateway'?'checked':''}> <span><b>Gateway / UTM</b> — firewall, NAT, WAN↔LAN routing, VPN, IDS/IPS. Uređaj je rub mreže (perimeter) između interneta i LAN-a.</span></label>
<label class="radio"><input type="radio" name="prof" value="router" ${p==='router'?'checked':''}> <span><b>Lokalni router</b> — samo DHCP, DNS i routing između lokalnih mreža. Bez NAT-a i perimetar firewalla; uređaj stoji iza postojećeg gatewaya.</span></label>
<div><button type="submit">Spremi način rada</button></div>
<div id="spMsg" class="muted">Trenutno: <b>${p==='gateway'?'Gateway / UTM':'Lokalni router'}</b></div></form>
${help('Odaberi <b>Gateway/UTM</b> kad je Saguaro glavni ulaz u mrežu (spojen na internet/WAN) i treba raditi firewall, NAT i VPN. Odaberi <b>Lokalni router</b> kad već imaš drugi firewall/gateway (npr. postojeći ruter ili firewall), a Saguaro služi samo kao interni DHCP/DNS poslužitelj i router između lokalnih segmenata. Prije prelaska u Router mod isključi Gateway (WAN/NAT) u modulu Gateway ako je aktivan — inače prebacivanje neće proći.')}
</div>`;
$('#spForm').onsubmit=async e=>{e.preventDefault();const v=document.querySelector('input[name=prof]:checked').value;$('#spMsg').textContent='Spremam…';try{await api('/api/system/profile',{method:'PUT',body:JSON.stringify({profile:v})});sysProfile=await api('/api/system');renderNav();$('#spMsg').innerHTML='Spremljeno. Način rada: <b>'+(v==='gateway'?'Gateway / UTM':'Lokalni router')+'</b>'}catch(err){$('#spMsg').textContent=err.message}}}
function isWgKey(s){return /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(s)}
function isHostPort(s){const i=s.lastIndexOf(':');if(i<1)return false;const p=parseInt(s.slice(i+1),10);return p>=1&&p<=65535}
async function s2sPage(){const s=await api('/api/s2s');const sites=s.sites||[];const e=escapeHtml;
const keyPanel=s.serverPub?`<div class="panel"><h3>Za udaljeni uređaj</h3>
<p class="muted">Zalijepi ovaj <code>[Peer]</code> blok u WireGuard na drugoj lokaciji. Ako je ovaj uređaj pasivan (bez Endpointa prema njima), dodaj i našu javnu adresu kao njihov Endpoint <code>:${s.listenPort}</code>.</p>
<pre class="muted" style="white-space:pre-wrap">${e(s.remotePeerSnippet||'')}</pre>
<p class="muted">Naš javni ključ: <code>${e(s.serverPub)}</code></p></div>`:'';
const rows=sites.length?sites.map(t=>`<tr><td><b>${e(t.name)}</b></td><td class="muted">${e(t.endpoint||'pasivno')}</td><td>${e((t.remoteNetworks||[]).join(', '))}</td><td class="muted">${t.keepalive||0}s</td><td>${t.hasPsk?'<span class="badge">PSK</span>':'<span class="muted">—</span>'}</td><td><button class="s2sDel danger" data-n="${e(t.name)}">Obriši</button></td></tr>`).join(''):'<tr><td colspan="6" class="muted">Nema tunela.</td></tr>';
$('#content').innerHTML=`<div class="panel"><h2>Site-to-Site VPN ${s.enabled?'<span class="badge">aktivan</span>':''}</h2>
<p class="muted">WireGuard tunel mreža↔mreža između dvije lokacije. Ovaj i udaljeni uređaj razmijene javne ključeve; promet za udaljene mreže ide kroz tunel. Zaseban je od road-warrior VPN-a (drugo sučelje wgs2s).</p>
${help('<b>1.</b> Uključi sučelje i spremi — uređaj generira svoj ključni par i pokaže <b>javni ključ</b> + gotov <code>[Peer]</code> blok. <b>2.</b> Na <b>drugoj</b> lokaciji zalijepi taj blok u njihov WireGuard i uzmi <b>njihov</b> javni ključ + endpoint. <b>3.</b> Ovdje dodaj tunel: njihov javni ključ, njihov <b>Endpoint</b> (javni IP:port — ostavi prazno ako oni spajaju prema nama), i <b>udaljene mreže</b> (CIDR koje su iza njih, npr. <code>192.168.20.0/24</code>). <b>Naše lokalne mreže</b> upiši da se ispravno generira njihov blok. <b>PSK</b> (opcionalno, <code>wg genpsk</code>) daje dodatnu zaštitu. Za rad je potreban otvoren UDP port na obje strane i dozvoljen forwarding.')}
<form id="s2sForm" class="stack">
<label><input id="s2sEnabled" type="checkbox" ${s.enabled?'checked':''}> Uključi site-to-site sučelje (wgs2s)</label>
<label>Listen port (UDP) <input id="s2sPort" type="number" min="1" max="65535" value="${s.listenPort||51821}"></label>
<label>Tunel adresa (opcionalno, CIDR) <input id="s2sTun" value="${e(s.tunnelAddress||'')}" placeholder="10.9.0.1/30"></label>
<label>Naše lokalne mreže (CIDR, odvoji zarezom) <input id="s2sLocal" value="${e((s.localNetworks||[]).join(', '))}" placeholder="192.168.10.0/24"></label>
<div><button type="submit">Spremi sučelje</button></div>
<div id="s2sMsg" class="muted"></div></form></div>
${keyPanel}
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h3 style="margin:0">Tuneli (${sites.length})</h3><button type="button" id="stNew">+ Dodaj tunel</button></div>
<table><thead><tr><th>Naziv</th><th>Endpoint</th><th>Udaljene mreže</th><th>Keepalive</th><th>PSK</th><th></th></tr></thead><tbody>${rows}</tbody></table>
<form id="s2sAdd" class="stack" style="${drawerStyle}"><h4 id="stFormTitle" style="margin:.1rem 0 .3rem">Novi tunel (udaljena lokacija)</h4>
<label>Naziv <input id="stName" placeholder="ured-zagreb" required></label>
<label>Njihov javni ključ <input id="stKey" placeholder="WireGuard public key" required></label>
<label>Njihov Endpoint (host:port, prazno = pasivno) <input id="stEp" placeholder="203.0.113.5:51821"></label>
<label>Udaljene mreže (CIDR, zarezom) <input id="stNets" placeholder="192.168.20.0/24" required></label>
<label>Keepalive (s, 0 = isključeno) <input id="stKa" type="number" min="0" max="65535" value="25"></label>
<label>Preshared key (opcionalno) <input id="stPsk" placeholder="wg genpsk (opcionalno)"></label>
<div class="btnrow"><button type="submit">Dodaj tunel</button> <button type="button" id="stCancel" class="ghost">Odustani</button></div>
<div id="stMsg" class="muted"></div></form></div>`;
$('#s2sForm').onsubmit=async ev=>{ev.preventDefault();const m=$('#s2sMsg');m.textContent='';
const tun=$('#s2sTun').value.trim();const local=$('#s2sLocal').value.split(',').map(x=>x.trim()).filter(Boolean);
if(tun&&!isCIDR(tun)){m.textContent='Tunel adresa mora biti CIDR (npr. 10.9.0.1/30).';return}
for(const n of local){if(!isCIDR(n)){m.textContent='Neispravna lokalna mreža: '+n;return}}
m.textContent='Primjena…';try{await api('/api/s2s/apply',{method:'POST',body:JSON.stringify({enabled:$('#s2sEnabled').checked,listenPort:parseInt($('#s2sPort').value,10)||51821,tunnelAddress:tun,localNetworks:local})});s2sPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.s2sDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati tunel ${el.dataset.n}?`))return;try{await api(`/api/s2s/sites/${encodeURIComponent(el.dataset.n)}`,{method:'DELETE'});s2sPage()}catch(err){alert(err.message)}});
makeDrawer({form:'s2sAdd',title:'stFormTitle',newBtn:'stNew',cancel:'stCancel',addTitle:'Novi tunel (udaljena lokacija)',reset:()=>{$('#s2sAdd').reset();$('#stMsg').textContent=''},focus:'stName'});
$('#s2sAdd').onsubmit=async ev=>{ev.preventDefault();const m=$('#stMsg');m.textContent='';
const key=$('#stKey').value.trim(),ep=$('#stEp').value.trim(),nets=$('#stNets').value.split(',').map(x=>x.trim()).filter(Boolean),psk=$('#stPsk').value.trim();
if(!isWgKey(key)){m.textContent='Javni ključ nije ispravan WireGuard ključ.';return}
if(ep&&!isHostPort(ep)){m.textContent='Endpoint mora biti host:port.';return}
if(!nets.length){m.textContent='Upiši barem jednu udaljenu mrežu (CIDR).';return}
for(const n of nets){if(!isCIDR(n)){m.textContent='Neispravna mreža: '+n;return}}
if(psk&&!isWgKey(psk)){m.textContent='PSK mora biti base64 WireGuard ključ (wg genpsk).';return}
m.textContent='Dodajem…';try{await api('/api/s2s/sites',{method:'POST',body:JSON.stringify({name:$('#stName').value.trim(),pubKey:key,endpoint:ep,remoteNetworks:nets,keepalive:parseInt($('#stKa').value,10)||0,psk:psk})});s2sPage()}catch(err){m.textContent=err.message}}}
function isPsk(s){return /^[A-Za-z0-9._~!@#$%^&*()+=:;,/?|-]{8,64}$/.test(s)}
function isProposal(s){return /^[a-z0-9]+(-[a-z0-9]+)*$/.test(s)}
async function ipsecPage(){const s=await api('/api/ipsec');const conns=s.connections||[];const e=escapeHtml;
const dike=s.defaultIke||'aes256-sha256-modp2048',desp=s.defaultEsp||'aes256-sha256-modp2048';
const authOk=c=>(c.auth==='cert')?(c.hasCert&&c.hasKey&&c.hasCa):c.hasPsk;
const rows=conns.length?conns.map(c=>`<tr><td><b>${e(c.name)}</b></td><td>${e(c.remoteAddr)}</td><td class="muted">${e((c.localSubnets||[]).join(', '))} → ${e((c.remoteSubnets||[]).join(', '))}</td><td class="muted">${c.initiate?'start':'on-demand'}</td><td><span class="badge">${e(c.auth||'psk')}</span>${authOk(c)?'':' <span class="st-error">⚠</span>'}</td><td><button class="ipDel danger" data-n="${e(c.name)}">Obriši</button></td></tr>`).join(''):'<tr><td colspan="6" class="muted">Nema tunela.</td></tr>';
$('#content').innerHTML=`<div class="panel"><h2>IPsec IKEv2 ${s.enabled?'<span class="badge">aktivan</span>':''}</h2>
<p class="muted">Site-to-site tunel prema uređajima koji ne koriste WireGuard (FortiGate, MikroTik, Cisco…). IKEv2 s preshared ključem.</p>
${help('Obje strane moraju imati <b>iste postavke</b>: isti <b>preshared key</b>, iste <b>proposal</b> algoritme (default <code>'+e(dike)+'</code>) i <b>zrcalne</b> mreže — naše <b>Lokalne mreže</b> su njihove udaljene i obrnuto. <b>Remote adresa</b> je javni IP/FQDN drugog uređaja. <b>Initiate</b> uključi na strani koja prva uspostavlja tunel (druga strana čeka); ako obje imaju stalni IP, može bilo koja. <b>ID</b> ostavi prazno da se koristi IP, ili upiši npr. FQDN/@ime ako to peer traži. Na drugom uređaju: IPsec → IKEv2, Authentication = Preshared key, Local/Remote subnets zrcalno, isti algoritmi. Potreban je otvoren UDP 500/4500 prema nama i dozvoljen forwarding.')}
<div class="wizRow">${conns.length?`<button id="ipToggle">${s.enabled?'Isključi IPsec':'Uključi IPsec'}</button>`:'<span class="muted">Dodaj barem jedan tunel pa ga možeš uključiti.</span>'}</div>
<div id="ipMsg" class="muted"></div></div>
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h3 style="margin:0">Tuneli (${conns.length})</h3><button type="button" id="ipNew">+ Dodaj tunel</button></div>
<table><thead><tr><th>Naziv</th><th>Remote</th><th>Lokalno → Udaljeno</th><th>Način</th><th>Auth</th><th></th></tr></thead><tbody>${rows}</tbody></table>
<form id="ipAdd" class="stack" style="${drawerStyle}"><h4 id="ipFormTitle" style="margin:.1rem 0 .3rem">Novi tunel</h4>
<label>Naziv <input id="ipName" placeholder="ured-hq" required></label>
<label>Remote adresa (IP ili FQDN) <input id="ipRemote" placeholder="203.0.113.5" required></label>
<label>Naše lokalne mreže (CIDR, zarezom) <input id="ipLocal" placeholder="192.168.10.0/24" required></label>
<label>Udaljene mreže (CIDR, zarezom) <input id="ipRemNets" placeholder="192.168.20.0/24" required></label>
<label>Local ID (opcionalno) <input id="ipLid" placeholder="prazno = naš IP"></label>
<label>Remote ID (opcionalno) <input id="ipRid" placeholder="prazno = remote adresa"></label>
<label>IKE proposal <input id="ipIke" value="${e(dike)}"></label>
<label>ESP proposal <input id="ipEsp" value="${e(desp)}"></label>
<label><input id="ipInit" type="checkbox" checked> Initiate (ova strana uspostavlja tunel)</label>
<label>Autentikacija <select id="ipAuth"><option value="psk">Preshared key (PSK)</option><option value="cert">Certifikat (X.509)</option></select></label>
<div id="ipPskWrap"><label>Preshared key <input id="ipPsk" placeholder="8-64 znaka (prazno = zadrži postojeći)"></label></div>
<div id="ipCertWrap" style="display:none">
<label>Naš certifikat (PEM) <textarea id="ipCert" rows="3" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
<label>Naš privatni ključ (PEM, prazno = zadrži) <textarea id="ipKey" rows="3" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label>
<label>CA certifikat udaljene strane (PEM) <textarea id="ipCa" rows="3" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
<p class="muted">Za certifikate su <b>Local ID</b> i <b>Remote ID</b> obavezni i moraju odgovarati identitetima u certifikatima (npr. CN/SAN). Certifikate možeš izdati u modulu <b>Certificates</b> ili unijeti tuđe.</p></div>
<div class="btnrow"><button type="submit">Spremi tunel</button> <button type="button" id="ipCancel" class="ghost">Odustani</button></div>
<div id="ipaMsg" class="muted"></div></form></div>`;
if($('#ipToggle'))$('#ipToggle').onclick=async()=>{const m=$('#ipMsg');m.textContent='Primjena…';try{await api('/api/ipsec/apply',{method:'POST',body:JSON.stringify({enabled:!s.enabled})});ipsecPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.ipDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati tunel ${el.dataset.n}?`))return;try{await api(`/api/ipsec/connections/${encodeURIComponent(el.dataset.n)}`,{method:'DELETE'});ipsecPage()}catch(err){alert(err.message)}});
$('#ipAuth').onchange=()=>{const cert=$('#ipAuth').value==='cert';$('#ipPskWrap').style.display=cert?'none':'';$('#ipCertWrap').style.display=cert?'':'none'};
makeDrawer({form:'ipAdd',title:'ipFormTitle',newBtn:'ipNew',cancel:'ipCancel',addTitle:'Novi tunel',reset:()=>{$('#ipAdd').reset();$('#ipPskWrap').style.display='';$('#ipCertWrap').style.display='none';$('#ipaMsg').textContent=''},focus:'ipName'});
$('#ipAdd').onsubmit=async ev=>{ev.preventDefault();const m=$('#ipaMsg');m.textContent='';
const local=$('#ipLocal').value.split(',').map(x=>x.trim()).filter(Boolean),rem=$('#ipRemNets').value.split(',').map(x=>x.trim()).filter(Boolean);
const ike=$('#ipIke').value.trim()||dike,esp=$('#ipEsp').value.trim()||desp,auth=$('#ipAuth').value,psk=$('#ipPsk').value.trim();
const lid=$('#ipLid').value.trim(),rid=$('#ipRid').value.trim();
if(!$('#ipRemote').value.trim()){m.textContent='Upiši remote adresu.';return}
if(!local.length||!rem.length){m.textContent='Upiši barem jednu lokalnu i jednu udaljenu mrežu.';return}
for(const n of local.concat(rem)){if(!isCIDR(n)){m.textContent='Neispravna mreža: '+n;return}}
if(!isProposal(ike)||!isProposal(esp)){m.textContent='Proposal smije sadržavati samo mala slova, brojke i crtice (npr. aes256-sha256-modp2048).';return}
const body={name:$('#ipName').value.trim(),remoteAddr:$('#ipRemote').value.trim(),localSubnets:local,remoteSubnets:rem,localId:lid,remoteId:rid,ikeProposal:ike,espProposal:esp,initiate:$('#ipInit').checked,auth};
if(auth==='cert'){if(!lid||!rid){m.textContent='Za certifikat su Local ID i Remote ID obavezni.';return}
const cert=$('#ipCert').value.trim(),key=$('#ipKey').value.trim(),ca=$('#ipCa').value.trim();
if(cert&&!cert.includes('BEGIN CERTIFICATE')){m.textContent='Naš certifikat mora biti PEM.';return}
if(ca&&!ca.includes('BEGIN CERTIFICATE')){m.textContent='CA certifikat mora biti PEM.';return}
body.localCert=cert;body.localKey=key;body.remoteCa=ca;}
else{if(psk&&!isPsk(psk)){m.textContent='PSK mora imati 8-64 znaka, bez navodnika, razmaka i obrnute kose crte.';return}body.psk=psk;}
m.textContent='Spremam…';try{await api('/api/ipsec/connections',{method:'POST',body:JSON.stringify(body)});ipsecPage()}catch(err){m.textContent=err.message}}}
function svcState(s){return({active:'st-healthy',inactive:'st-muted',failed:'st-error',activating:'st-unknown',deactivating:'st-unknown'})[s]||'st-unknown'}
async function servicesCtlPage(){const list=await api('/api/svcctl');const e=escapeHtml;
const rows=list.map(s=>`<tr><td><b>${e(s.name)}</b><div class="muted" style="font-size:12px">${e(s.key)}</div></td>
<td><span class="status ${svcState(s.state)}">${e(s.state)}</span></td>
<td><div class="rowacts">${iconBtn('play','Start','',`data-k="${e(s.key)}" data-a="start"`).replace('iconbtn','iconbtn svcAct')}${iconBtn('restart','Restart','',`data-k="${e(s.key)}" data-a="restart"`).replace('iconbtn','iconbtn svcAct')}${iconBtn('stop','Stop','danger',`data-k="${e(s.key)}" data-a="stop"`).replace('iconbtn','iconbtn svcAct')}</div></td></tr>`).join('');
$('#content').innerHTML=`<div class="panel"><h2>Servisi (${list.length})</h2>
<p class="muted">Ručno upravljanje appliance servisima za troubleshooting. Stanje se osvježava pri svakom otvaranju.</p>
${help('Koristi kad se neki servis "zaglavi" ili nakon promjene konfiguracije: <b>Restart</b> ponovno pokreće servis, <b>Stop</b> ga zaustavlja, <b>Start</b> pokreće. Oprez: <b>nftables</b> stop uklanja firewall, <b>nginx</b> stop gasi ovaj GUI (do restarta), <b>postgresql</b> stop obara DHCP/DNS bazu i event log. Sam upravljački servis (saguaro) namjerno nije na popisu da ga ne možeš ugasiti iz sučelja. Servisi koji nisu konfigurirani prikazuju <i>inactive</i> — to je normalno.')}
<table><thead><tr><th>Servis</th><th>Stanje</th><th>Akcije</th></tr></thead><tbody>${rows}</tbody></table>
<div id="svcMsg" class="muted"></div></div>`;
document.querySelectorAll('.svcAct').forEach(el=>el.onclick=async()=>{const k=el.dataset.k,a=el.dataset.a;
if((a==='stop'||a==='restart')&&!confirm(`${a==='stop'?'Zaustaviti':'Restartati'} servis ${k}?`))return;
const msg=$('#svcMsg');msg.textContent=`${a} ${k}…`;
document.querySelectorAll('.svcAct').forEach(b=>b.disabled=true);
try{const r=await api(`/api/svcctl/${encodeURIComponent(k)}/${a}`,{method:'POST',body:'{}'});msg.textContent=`${k}: ${r.state}`;servicesCtlPage()}catch(err){msg.textContent=err.message;document.querySelectorAll('.svcAct').forEach(b=>b.disabled=false)}})}
async function packagesPage(){const e=escapeHtml;let me={role:''};try{me=await api('/api/profile')}catch(_){}
const admin=me.role==='admin';
const inv=await api('/api/packages');const pkgs=inv.packages||[];const un=inv.unattended||{};
const su=await api('/api/selfupdate').catch(()=>({version:'?'}));
const suBehind=(su.behind||0)>0;
let suRefs={branches:[],tags:[]};
if(su.gitRepo&&admin){suRefs=await api('/api/selfupdate/refs').catch(()=>({branches:[],tags:[]}))}
const refOpts=['<option value="">origin/main (zadano — najnovije)</option>']
  .concat((suRefs.branches||[]).filter(b=>b!=='origin/main').map(b=>`<option value="${e(b)}">grana: ${e(b)}</option>`))
  .concat((suRefs.tags||[]).map(t=>`<option value="${e(t)}">tag: ${e(t)}</option>`)).join('');
const suControls=admin?`<div class="wizRow" style="align-items:center;flex-wrap:wrap">
<select id="suRef" title="Verzija / grana / tag za primjenu">${refOpts}</select>
<button id="suApply" ${suBehind?'':'class="ghost"'}>Ažuriraj Saguaro${suBehind?' ('+su.behind+')':''}</button>
${su.previous?`<button id="suRollback" class="ghost" title="Vrati na commit prije zadnjeg ažuriranja">Vrati na ${e(su.previous)}</button>`:''}
${su.buildable===false?'<span class="muted">Go toolchain nije dostupan, build nije moguć.</span>':''}</div><div id="suMsg" class="muted"></div>`
:'<span class="muted">Samo admin može ažurirati control plane.</span>';
const suPanel=`<div class="panel"><h2>Saguaro sustav (control plane)</h2>
<p class="muted">Trenutna verzija: <b>v${e(su.version||'?')}</b>${su.current?` · commit <code>${e(su.current)}</code>`:''}. ${su.gitRepo?(suBehind?`<b class="up">${su.behind} promjena</b> dostupno na gitu (remote <code>${e(su.remote||'')}</code>).`:'U toku s gitom.'):'Instalirano iz .deb paketa — ažuriraj kroz komponentu <b>control plane</b> u tablici ispod ili preuzmi novi .deb.'}</p>
${help('Ovdje se ažurira <b>sam Saguaro Network Manager</b> (control plane + adapteri + sudoers), ne samo OS servisi. Kod git-instalacije odaberi <b>verziju</b> (zadano <code>origin/main</code> — najnovije, ili konkretan tag/grana); <b>Ažuriraj</b> radi <code>git fetch</code> + hard-reset na tu verziju, ponovno gradi binarije, osvježava adaptere i sudoers (uz validaciju) i restarta servis (~par sekundi prekida GUI-ja). <b>Vrati na …</b> vraća na commit koji je radio prije zadnjeg ažuriranja (rollback). Smije samo <b>admin</b>.')}
${su.gitRepo?suControls:''}</div>`;
const verCell=p=>{if(!p.installed)return '<span class="muted">nije instaliran</span>';if(p.upgradable)return `${e(p.installed)} → <b class="up">${e(p.candidate)}</b>`;return `${e(p.installed)} <span class="muted">(najnovije)</span>`};
const rows=pkgs.map(p=>`<tr><td><b>${e(p.name)}</b><div class="muted" style="font-size:12px">${e(p.package)}</div></td>
<td>${verCell(p)}</td>
<td>${p.upgradable?(admin?`<button class="pkgUp" data-k="${e(p.key)}">Ažuriraj</button>`:'<span class="badge">dostupno</span>'):'<span class="status st-healthy">OK</span>'}</td></tr>`).join('');
const banner=inv.upgradable>0?`<div class="panel error"><b>${inv.upgradable}</b> ${inv.upgradable===1?'paket ima':'paketa ima'} dostupno ažuriranje.</div>`:'<div class="panel"><span class="status st-healthy">Svi paketi su ažurni.</span></div>';
$('#content').innerHTML=`${suPanel}<div class="panel"><h2>Ažuriranja servisa i paketa</h2>
<p class="muted">Instalirane vs. dostupne verzije appliance komponenti. Ažuriranje se radi <b>po jednom paketu</b> (nikad slijepi <code>apt upgrade</code>) da izbjegneš neočekivane restarte više servisa odjednom.</p>
${help('<b>Osvježi popis</b> pokreće <code>apt update</code> (dohvat dostupnih verzija). <b>Ažuriraj</b> nadograđuje samo taj jedan paket i čuva postojeću konfiguraciju (<code>--force-confold</code>); servis se može nakratko restartati. Preporuka za firewall: ažuriraj u prozoru održavanja i provjeri rad nakon toga. <b>Automatska sigurnosna ažuriranja</b> uključuju Ubuntu <i>unattended-upgrades</i> koji u pozadini primjenjuje samo sigurnosne zakrpe. Ažuriranja i automatiku smije mijenjati samo <b>admin</b>.')}
${banner}
<div class="wizRow"><button id="pkgRefresh">Osvježi popis (apt update)</button></div><div id="pkgMsg" class="muted"></div>
<table><thead><tr><th>Komponenta</th><th>Verzija</th><th>Akcija</th></tr></thead><tbody>${rows}</tbody></table></div>
<div class="panel"><h3>Automatska sigurnosna ažuriranja</h3>
<p class="muted">Ubuntu <code>unattended-upgrades</code> — automatska primjena <b>samo sigurnosnih</b> zakrpa. Paket: ${un.installed?'<span class="status st-healthy">instaliran</span>':'<span class="muted">nije instaliran</span>'}, stanje: ${un.enabled?'<span class="status st-healthy">uključeno</span>':'<span class="status st-muted">isključeno</span>'}.</p>
${admin?toggle('pkgUnat',un.enabled,'Uključi automatska sigurnosna ažuriranja')+'<div id="pkgUnMsg" class="muted"></div>':'<p class="muted">Samo admin može mijenjati ovu postavku.</p>'}</div>`;
$('#pkgRefresh').onclick=async()=>{const btn=$('#pkgRefresh'),msg=$('#pkgMsg');btn.disabled=true;msg.textContent='apt update… (može potrajati)';try{await api('/api/packages/refresh',{method:'POST',body:'{}'});msg.textContent='Popis osvježen.';packagesPage()}catch(err){msg.textContent=err.message;btn.disabled=false}};
const suBtn=$('#suApply');if(suBtn)suBtn.onclick=async()=>{const ref=($('#suRef')||{}).value||'';const label=ref||'origin/main (najnovije)';if(!confirm('Ažurirati Saguaro control plane na '+label+'? Gradi binarije i restarta servis (~par sekundi prekida GUI-ja).'))return;const msg=$('#suMsg');suBtn.disabled=true;msg.textContent='Povlačim i gradim… (može potrajati minutu)';try{const r=await api('/api/selfupdate/apply',{method:'POST',body:JSON.stringify({ref})});msg.textContent=(r.message||'Ažurirano')+' — GUI se restarta, osvježi stranicu za par sekundi.'}catch(err){msg.textContent=err.message;suBtn.disabled=false}};
const suRb=$('#suRollback');if(suRb)suRb.onclick=async()=>{if(!confirm('Vratiti control plane na prethodni commit ('+(su.previous||'')+')? Gradi i restarta servis (~par sekundi prekida GUI-ja).'))return;const msg=$('#suMsg');suRb.disabled=true;msg.textContent='Vraćam na prethodnu verziju i gradim…';try{const r=await api('/api/selfupdate/rollback',{method:'POST',body:'{}'});msg.textContent=(r.message||'Vraćeno')+' — GUI se restarta, osvježi stranicu za par sekundi.'}catch(err){msg.textContent=err.message;suRb.disabled=false}};
document.querySelectorAll('.pkgUp').forEach(el=>el.onclick=async()=>{const k=el.dataset.k;if(!confirm(`Ažurirati paket ${k}? Servis se može nakratko restartati.`))return;const msg=$('#pkgMsg');document.querySelectorAll('.pkgUp').forEach(b=>b.disabled=true);msg.textContent=`Ažuriram ${k}… (može potrajati)`;try{const r=await api(`/api/packages/upgrade/${encodeURIComponent(k)}`,{method:'POST',body:'{}'});msg.textContent=`${k} ažuriran.`;packagesPage()}catch(err){msg.textContent=err.message;document.querySelectorAll('.pkgUp').forEach(b=>b.disabled=false)}});
const un2=$('#pkgUnat');if(un2)un2.onchange=async()=>{const msg=$('#pkgUnMsg');un2.disabled=true;msg.textContent='Mijenjam…';try{await api('/api/packages/unattended',{method:'POST',body:JSON.stringify({enabled:un2.checked})});msg.textContent=un2.checked?'Automatska sigurnosna ažuriranja uključena.':'Isključeno.';un2.disabled=false}catch(err){msg.textContent=err.message;un2.disabled=false;un2.checked=!un2.checked}}}
function isRange(s){const p=s.split('-');return p.length===2&&isIPv4(p[0].trim())&&isIPv4(p[1].trim())}
// aliasesPage is the network-side entry point for firewall aliases: the same
// named objects the firewall and VPN use, edited here so servers/networks get a
// memorable name once and every rule that references them follows.
async function aliasesPage(){const f=await api('/api/firewall').catch(()=>({aliases:[]}));const aliases=f.aliases||[];const e=escapeHtml;
const putAliases=list=>api('/api/firewall/aliases',{method:'PUT',body:JSON.stringify({aliases:list})});
const rows=aliases.length?aliases.map((a,i)=>`<tr><td><b>${e(a.name)}</b></td><td class="muted">${e(a.type)}</td><td>${e((a.values||[]).join(', '))}</td><td><div class="rowacts">${iconBtn('edit','Uredi alias','',`data-i="${i}"`).replace('iconbtn','iconbtn alEdit')}${iconBtn('del','Obriši alias','danger',`data-i="${i}"`).replace('iconbtn','iconbtn alDel')}</div></td></tr>`).join(''):'<tr><td colspan="4" class="muted">Još nema aliasa. Dodaj prvi ispod.</td></tr>';
$('#content').innerHTML=`${help('Alias je <b>ime za IP, mrežu ili raspon</b> — npr. <code>server_rdp</code> = 10.10.10.50. Definiraš ga jednom, a koristiš po imenu u <b>firewall pravilima</b> i <b>VPN pristupu</b>. Promijeniš li IP, sva pravila prate — bez pamćenja adresa. Isti popis vidiš i pod <b>Vatrozid → Aliasi</b>.')}
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h2 style="margin:0">Aliasi (${aliases.length})</h2><button type="button" id="alNew">+ Dodaj alias</button></div>
<table><thead><tr><th>Naziv</th><th>Tip</th><th>Vrijednosti</th><th>Akcije</th></tr></thead><tbody>${rows}</tbody></table>
<form id="alAdd" class="stack" style="${drawerStyle}"><h4 id="alFormTitle" style="margin:.1rem 0 .3rem">Novi alias</h4>
<label>Naziv <input id="alName" placeholder="server_rdp" required></label>
<p class="muted small">Samo slova, brojke i <code>_</code> (počinje slovom). Bez razmaka i crtice — npr. <code>serveri_lan</code>, <code>dmz_web</code>.</p>
<label>Tip <select id="alType"><option value="host">host — jedna ili više IP adresa</option><option value="network">network — cijela mreža (CIDR)</option><option value="range">range — raspon IP-IP</option></select></label>
<label>Vrijednosti (zarezom) <input id="alVals" placeholder="10.10.10.50, 10.10.10.51" required></label>
<div class="btnrow"><button type="submit" id="alAddBtn">Dodaj alias</button> <button type="button" id="alCancel" class="ghost">Odustani</button></div><div id="alMsg" class="muted"></div></form></div>`;
let alEdit=-1;const alAddBtn=$('#alAddBtn');
const alReset=()=>{alEdit=-1;$('#alAdd').reset();if(alAddBtn)alAddBtn.textContent='Dodaj alias';$('#alMsg').textContent=''};
const alDrawer=makeDrawer({form:'alAdd',title:'alFormTitle',newBtn:'alNew',cancel:'alCancel',addTitle:'Novi alias',reset:alReset,focus:'alName'});
document.querySelectorAll('.alEdit').forEach(el=>el.onclick=()=>{const a=aliases[+el.dataset.i];alEdit=+el.dataset.i;$('#alName').value=a.name||'';$('#alType').value=a.type||'host';$('#alVals').value=(a.values||[]).join(', ');if(alAddBtn)alAddBtn.textContent='Spremi izmjene';$('#alMsg').textContent='';alDrawer.edit('Uredi alias — '+(a.name||''))});
document.querySelectorAll('.alDel').forEach(el=>el.onclick=async()=>{const a=aliases[+el.dataset.i];if(!confirm('Obrisati alias „'+a.name+'"? Pravila koja ga koriste ostat će bez odredišta.'))return;const list=aliases.filter((_,j)=>j!==+el.dataset.i);try{await putAliases(list);aliasesPage()}catch(err){alert(err.message)}});
$('#alAdd').onsubmit=async ev=>{ev.preventDefault();const m=$('#alMsg');const name=$('#alName').value.trim();const type=$('#alType').value;const vals=$('#alVals').value.split(',').map(x=>x.trim()).filter(Boolean);
if(!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name)){m.textContent='Naziv mora počinjati slovom i sadržavati samo slova, brojke i _ (bez crtice/razmaka).';return}
if(!vals.length){m.textContent='Upiši barem jednu vrijednost.';return}
if(aliases.some((a,j)=>a.name===name&&j!==alEdit)){m.textContent='Alias s tim imenom već postoji.';return}
const list=aliases.slice();if(alEdit>=0){list[alEdit]={name,type,values:vals}}else{list.push({name,type,values:vals})}
try{await putAliases(list);aliasesPage()}catch(err){m.textContent=err.message}};}

function schedTitle(s){if(!s)return'';const dn=['Ned','Pon','Uto','Sri','Čet','Pet','Sub'];const days=(s.days||[]).length?s.days.slice().sort((a,b)=>a-b).map(d=>dn[d]!==undefined?dn[d]:d).join(', '):'svi dani';const time=(s.start||s.end)?`${s.start||'00:00'}–${s.end||'24:00'}`:'cijeli dan';return `${days} · ${time}`}
async function fwRulesPage(){const f=await api('/api/firewall');const aliases=f.aliases||[],rules=f.rules||[],zones=f.zones||[];const e=escapeHtml;
const nics=await api('/api/interfaces').catch(()=>[]);
const gw=((await api('/api/gateway').catch(()=>({config:{}}))).config)||{};
// NAT rules are configured on the Gateway page; surface them here read-only in a
// Original -> Translated view so all rule types live in one place.
const gwWan=gw.wanInterface||'wan1',pf=gw.portForwards||[],sn=gw.snatRules||[];
const masq=!!(gw.gatewayEnabled&&gw.natEnabled!==false);
const natCount=(masq?1:0)+pf.length+sn.length;
let natBody='',nIdx=0;
if(masq){nIdx++;natBody+=`<tr><td>${nIdx}</td><td><b>Masquerade</b><div class="muted small">SNAT · LAN→WAN</div></td><td class="muted">izvor: LAN · odredište: bilo koje</td><td class="muted">izvor → WAN adresa</td><td class="muted">izlaz: ${e(nlabel(gwWan))}</td></tr>`}
pf.forEach(p=>{nIdx++;natBody+=`<tr><td>${nIdx}</td><td><b>Port forward</b><div class="muted small">DNAT</div></td><td class="muted">${e(nlabel(gwWan))} : ${p.extPort}/${e(p.proto)}</td><td class="muted">${e(p.destIp)} : ${p.destPort}</td><td class="muted">ulaz: ${e(nlabel(gwWan))}</td></tr>`});
sn.forEach(x=>{nIdx++;natBody+=`<tr><td>${nIdx}</td><td><b>SNAT</b><div class="muted small">po izvoru</div></td><td class="muted">izvor: ${e(x.source)}</td><td class="muted">→ ${e(x.toAddress)}</td><td class="muted">izlaz: ${e(nlabel(gwWan))}</td></tr>`});
if(!natBody)natBody=`<tr><td colspan="5" class="muted">Nema NAT pravila. Uključi NAT (masquerade) ili dodaj port-forward/SNAT u Gateway stranici.</td></tr>`;
const putAliases=list=>api('/api/firewall/aliases',{method:'PUT',body:JSON.stringify({aliases:list})});
const putRules=list=>api('/api/firewall/rules',{method:'PUT',body:JSON.stringify({rules:list})});
const putZones=list=>api('/api/firewall/zones',{method:'PUT',body:JSON.stringify({zones:list})});
const ZKINDS=[['lan','LAN (povjerljivo)'],['dmz','DMZ (poluizolirano)'],['guest','Gost (izolirano)'],['wan','WAN (nepovjerljivo)']];
const zkindLabel=k=>{const z=ZKINDS.find(x=>x[0]===k);return z?z[1]:k};
const zoneOpt=sel=>['<option value="">(bilo koja)</option>'].concat(zones.map(z=>`<option ${z.name===sel?'selected':''}>${e(z.name)}</option>`)).join('');
const zoneIfLabel=z=>e(nlabel(z.interface))+(z.vlanId?` <span class="badge">VLAN ${z.vlanId}</span> <span class="muted">${e(z.interface)}.${z.vlanId}</span>`:'');
const zoneRows=zones.length?zones.map((z,i)=>`<tr><td><b>${e(z.name)}</b></td><td><span class="badge">${e(zkindLabel(z.kind))}</span></td><td>${zoneIfLabel(z)}</td><td class="muted">${e(z.network||'—')}${z.vlanId&&z.address?' · '+e(z.address):''}</td><td><div class="rowacts">${z.kind!=='wan'&&z.network?`<button type="button" class="ghost znDhcp" data-i="${i}" title="Napravi DHCP subnet za ovu zonu">DHCP</button>`:''}${iconBtn('del','Obriši zonu','danger',`data-i="${i}"`).replace('iconbtn','iconbtn znDel')}</div></td></tr>`).join(''):'<tr><td colspan="5" class="muted">Nema definiranih zona (vrijedi osnovna LAN↔WAN politika).</td></tr>';
const hasVlan=zones.some(z=>z.vlanId);
const hasInternalZone=zones.some(z=>z.kind!=='wan'&&z.network);
const pend=f.pending?`<div class="panel error"><h2>⚠ Promjena firewalla čeka potvrdu</h2><p>Bez potvrde unutar 120 s vraća se prethodna konfiguracija.</p><button id="fwConfirm">Potvrdi (zadrži)</button> <button id="fwRollback" class="ghost">Vrati odmah</button></div>`:'';
const aliasRows=aliases.length?aliases.map((a,i)=>`<tr><td><b>${e(a.name)}</b></td><td class="muted">${e(a.type)}</td><td>${e((a.values||[]).join(', '))}</td><td><div class="rowacts">${iconBtn('edit','Uredi alias','',`data-i="${i}"`).replace('iconbtn','iconbtn alEdit')}${iconBtn('del','Obriši alias','danger',`data-i="${i}"`).replace('iconbtn','iconbtn alDel')}</div></td></tr>`).join(''):'<tr><td colspan="4" class="muted">Nema aliasa.</td></tr>';
const aliasVals=n=>{const a=aliases.find(x=>x.name===n);return a?(a.values||[]).join(', '):''};
const firstVal=n=>{const a=aliases.find(x=>x.name===n);const v=a&&a.values&&a.values[0]?a.values[0]:'';return v.split('-')[0].split('/')[0]};
const aliasOpt=sel=>['<option value="">(bilo koji)</option>'].concat(aliases.map(a=>`<option ${a.name===sel?'selected':''}>${e(a.name)}</option>`)).join('');
const CATS=[['','(bez)'],['lan2wan','LAN → WAN'],['wan2lan','WAN → LAN'],['wan2dmz','WAN → DMZ'],['vpn','VPN'],['local','Local (firewall)'],['other','Ostalo']];
const catLabel=c=>{const f=CATS.find(x=>x[0]===c);return f?f[1]:c};
const catOpts=sel=>CATS.map(([v,l])=>`<option value="${v}" ${v===sel?'selected':''}>${l}</option>`).join('');
const actClass=a=>a==='accept'?'st-healthy':(a==='drop'||a==='reject')?'st-error':'';
const ruleRows=rules.length?rules.map((r,i)=>{const acts=`<div class="rowacts">${iconBtn('up','Pomakni gore','',`data-i="${i}"${i===0?' disabled':''}`).replace('iconbtn','iconbtn ruUp')}${iconBtn('down','Pomakni dolje','',`data-i="${i}"${i===rules.length-1?' disabled':''}`).replace('iconbtn','iconbtn ruDown')}${iconBtn('test','Testiraj ovo pravilo','',`data-i="${i}"`).replace('iconbtn','iconbtn ruTestBtn')}${iconBtn('edit','Uredi pravilo','',`data-i="${i}"`).replace('iconbtn','iconbtn ruEdit')}${iconBtn('del','Obriši pravilo','danger',`data-i="${i}"`).replace('iconbtn','iconbtn ruDel')}</div>`;
const main=`<tr class="expandable" data-cat="${e(r.category||'')}" data-i="${i}" data-action="${e(r.action||'')}" data-enabled="${r.enabled?'1':'0'}" data-name="${e((r.name||'').toLowerCase())}"><td class="muted"><span class="chev">▶</span> ${i+1}</td><td>${r.enabled?'':'<span class="muted">(off) </span>'}<b>${e(r.name)}</b>${r.log?'<span class="chip chip-log">LOG</span>':''}${(r.fromZone||r.toZone)?`<span class="chip chip-zone">${e(r.fromZone||'*')}→${e(r.toZone||'*')}</span>`:''}${r.schedule?`<span class="chip chip-zone" title="Raspored: ${e(schedTitle(r.schedule))}">⏰ ${e(schedTitle(r.schedule))}</span>`:''}</td><td>${r.category?`<span class="badge">${e(catLabel(r.category))}</span>`:'<span class="muted">—</span>'}</td><td><span class="status ${actClass(r.action)}">${e(r.action)}</span></td><td class="muted">${e(r.proto)}${r.dstPort?':'+r.dstPort:''}</td><td>${e(r.srcAlias||'any')} → ${e(r.dstAlias||'any')}</td><td class="muted small" data-cnt="${e(r.name)}">—</td><td>${acts}</td></tr>`;
const dl=(t,d)=>`<dl><dt>${t}</dt><dd>${d}</dd></dl>`;
const detail=`<tr class="row-detail hidden" data-detail="${i}" data-cat="${e(r.category||'')}"><td colspan="8"><div class="detail-inner">${dl('Stanje',r.enabled?'<span class="status st-healthy">omogućeno</span>':'<span class="status st-muted">onemogućeno</span>')}${dl('Akcija',`<span class="status ${actClass(r.action)}">${e(r.action)}</span>`)}${dl('Protokol',e(r.proto)+(r.dstPort?' · port '+r.dstPort:''))}${dl('Kategorija',r.category?e(catLabel(r.category)):'—')}${dl('Izvor ('+e(r.srcAlias||'any')+')',e(r.srcAlias?aliasVals(r.srcAlias):'bilo koji')||'—')}${dl('Odredište ('+e(r.dstAlias||'any')+')',e(r.dstAlias?aliasVals(r.dstAlias):'bilo koji')||'—')}${(r.fromZone||r.toZone)?dl('Zona',e(r.fromZone||'bilo koja')+' → '+e(r.toZone||'bilo koja')):''}${dl('Logiranje',r.log?'<span class="status st-healthy">uključeno</span>':'<span class="muted">isključeno</span>')}${r.schedule?dl('Raspored',e(schedTitle(r.schedule))):''}</div></td></tr>`;
return main+detail}).join(''):'<tr><td colspan="8" class="muted">Nema pravila.</td></tr>';
$('#content').innerHTML=`${pend}
<div class="panel"><h2>Firewall aliasi i pravila</h2>
<p class="muted">Imenovani objekti (host / mreža / raspon) i custom pravila koja ih koriste po imenu. Pravila se primjenjuju u forward lancu, po redoslijedu odozgo, prije općeg LAN→WAN propuštanja — drop/reject ima prednost. Aktivni VPN tuneli (WireGuard site-to-site, IPsec) automatski se propuštaju kroz forward policy pri primjeni — nakon dodavanja tunela ponovno primijeni firewall.</p>
${help('<b>1.</b> Napravi <b>alias</b>: ime (počinje slovom, a-z 0-9 _), tip <code>host</code> (jedan/više IP-a), <code>network</code> (CIDR) ili <code>range</code> (<code>192.168.1.10-192.168.1.20</code>), i vrijednosti odvojene zarezom. <b>2.</b> Napravi <b>pravilo</b> koje povuče alias po imenu: akcija (accept/drop/reject), protokol, izvorni i odredišni alias (prazno = bilo koji) i opcionalno port. <b>3.</b> Klikni <b>Primijeni</b> — ruleset se učita s 120 s prozorom za potvrdu (ako izgubiš pristup, vraća se stara konfiguracija). Redoslijed pravila mijenjaj strelicama ↑↓. Pravila rade u <b>Gateway</b> modu.')}
${f.configured?'':'<div class="panel error">Najprije postavi <b>Gateway</b> (mgmt/klijentska mreža) da bi mogao primijeniti pravila.</div>'}
<div class="wizRow"><button id="fwApply">Primijeni firewall (120 s potvrda)</button></div><div id="fwMsg" class="muted"></div></div>
${tabBar('fwTabs',[['pravila','Pravila',rules.length],['nat','NAT pravila',natCount],['aliasi','Aliasi',aliases.length],['zone','Zone',zones.length],['geo','Geo-blokada'],['log','Log'],['test','Test pravila']])}
<div class="tabpane active" data-pane="fwTabs" data-tabkey="pravila">
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h3 style="margin:0">Pravila (${rules.length})</h3><button type="button" id="ruNew">+ Dodaj pravilo</button></div>
<div class="filterbar">
<input id="ruSearch" type="search" placeholder="Traži po nazivu…" autocomplete="off">
<select id="ruFilter"><option value="__all">Sve kategorije</option>${catOpts('')}</select>
<select id="ruFAction"><option value="__all">Sve akcije</option><option value="accept">accept</option><option value="drop">drop</option><option value="reject">reject</option></select>
<select id="ruFStatus"><option value="__all">Sva stanja</option><option value="1">Omogućena</option><option value="0">Onemogućena</option></select>
<button type="button" id="ruFReset" class="ghost">Poništi filtre</button>
</div>
<table><thead><tr><th>#</th><th>Naziv</th><th>Kategorija</th><th>Akcija</th><th>Proto</th><th>Izvor → Odredište</th><th>Promet</th><th>Akcije</th></tr></thead><tbody id="ruTbody">${ruleRows}</tbody></table>
<p class="muted">Klikni redak za detalje. Redoslijed određuje prioritet — pravila se primjenjuju odozgo; pomiči ikonama ↑↓. Kategorija je za grupiranje/filtriranje (LAN→WAN, WAN→LAN, VPN, Local…).</p>
<form id="ruAdd" class="stack" style="display:none;border:1px solid var(--line,#394150);border-radius:8px;padding:.7rem .9rem;margin:.5rem 0">
<h4 id="ruFormTitle" style="margin:.1rem 0 .3rem">Novo pravilo</h4>
<label>Naziv <input id="ruName" placeholder="blokiraj-goste" required></label>
<label>Akcija <select id="ruAction"><option value="accept">accept</option><option value="drop">drop</option><option value="reject">reject</option></select></label>
<label>Protokol <select id="ruProto"><option value="any">any</option><option value="tcp">tcp</option><option value="udp">udp</option></select></label>
<label>Izvor (alias) <select id="ruSrc">${aliasOpt('')}</select></label>
<label>Odredište (alias) <select id="ruDst">${aliasOpt('')}</select></label>
<label>Odredišni port (0 = svi) <input id="ruPort" type="number" min="0" max="65535" value="0"></label>
<label>Iz zone <select id="ruFromZone">${zoneOpt('')}</select></label>
<label>U zonu <select id="ruToZone">${zoneOpt('')}</select></label>
<label>Kategorija <select id="ruCat">${catOpts('')}</select></label>
${toggle('ruLog',false,'Logiraj promet koji pravilo uhvati (kernel log)')}
${toggle('ruEnabled',true,'Omogućeno')}
<fieldset style="border:1px solid var(--line,#394150);border-radius:6px;padding:.4rem .7rem;margin:.2rem 0"><legend class="muted small">Vremenski raspored (opcionalno)</legend>
<div class="filterbar" style="flex-wrap:wrap;gap:.5rem">${['Ned','Pon','Uto','Sri','Čet','Pet','Sub'].map((d,idx)=>`<label class="muted small" style="display:inline-flex;gap:.25rem;align-items:center;margin:0"><input type="checkbox" class="ruDay" value="${idx}">${d}</label>`).join('')}</div>
<div class="filterbar" style="gap:.7rem"><label class="muted small" style="margin:0">Od <input id="ruSchStart" type="time"></label><label class="muted small" style="margin:0">Do <input id="ruSchEnd" type="time"></label></div>
<p class="muted small" style="margin:.2rem 0 0">Prazno = pravilo je uvijek aktivno. Bez odabranih dana = svi dani. Raspon preko ponoći je dozvoljen (npr. 22:00–06:00). Vrijeme je po lokalnoj zoni kernela.</p></fieldset>
<div class="btnrow"><button type="submit" id="ruAddBtn">Dodaj pravilo</button> <button type="button" id="ruCancel" class="ghost">Odustani</button></div><div id="ruMsg" class="muted"></div></form></div>
<div class="panel"><h3>Brza blokada IP-a (blackhole)</h3>
<p class="muted small">Odmah odbaci sav <b>proslijeđeni</b> promet s IP adrese (npr. napadač iz sigurnosnog loga). Dodaje IP u <code>blocklist</code> alias + <b>drop pravilo na vrhu</b> (logirano). Ne dira mgmt pristup (forward lanac). Vrijedi odmah i trajno — bez 120 s potvrde.</p>
<div class="filterbar"><input id="blkIP" placeholder="npr. 203.0.113.5"><button type="button" id="blkAdd">Blokiraj IP</button></div>
<div id="blkList" class="muted">Učitavanje…</div><div id="blkMsg" class="muted"></div></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="nat">
<div class="panel"><h3>NAT pravila (${natCount})</h3>
<p class="muted">Prijevod adresa: <b>Masquerade/SNAT</b> (klijenti izlaze preko WAN adrese) i <b>DNAT / port-forward</b> (vanjski port → interni poslužitelj). NAT se <b>uređuje u Gateway stranici</b> — ovo je pregled svih NAT pravila na jednom mjestu.</p>
<table><thead><tr><th>#</th><th>Tip</th><th>Original</th><th>Prevedeno</th><th>Sučelje</th></tr></thead><tbody>${natBody}</tbody></table>
<div class="btnrow"><button type="button" id="fwNatEdit" class="ghost">Uredi u Gateway →</button></div></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="aliasi">
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h3 style="margin:0">Aliasi (${aliases.length})</h3><button type="button" id="alNew">+ Dodaj alias</button></div>
<table><thead><tr><th>Naziv</th><th>Tip</th><th>Vrijednosti</th><th>Akcije</th></tr></thead><tbody>${aliasRows}</tbody></table>
<form id="alAdd" class="stack" style="display:none;border:1px solid var(--line,#394150);border-radius:8px;padding:.7rem .9rem;margin:.5rem 0">
<h4 id="alFormTitle" style="margin:.1rem 0 .3rem">Novi alias</h4>
<label>Naziv <input id="alName" placeholder="serveri_lan" required></label>
<label>Tip <select id="alType"><option value="host">host (IP adrese)</option><option value="network">network (CIDR)</option><option value="range">range (IP-IP)</option></select></label>
<label>Vrijednosti (zarezom) <input id="alVals" placeholder="192.168.10.5, 192.168.10.6" required></label>
<div class="btnrow"><button type="submit" id="alAddBtn">Dodaj alias</button> <button type="button" id="alCancel" class="ghost">Odustani</button></div><div id="alMsg" class="muted"></div></form></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="zone">
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h3 style="margin:0">Zone (${zones.length})</h3><button type="button" id="znNew">+ Dodaj zonu</button></div>
<p class="muted">Segmentiraj mrežu po povjerenju. Zadana politika: zona veće razine povjerenja može otvarati promet prema nižoj (LAN→DMZ, DMZ→internet), nikad obrnuto — pa <b>DMZ ne doseže LAN</b>, a <b>Gost je izoliran</b> od svih. Sve što nije eksplicitno dopušteno (ili port-forward/pravilo) se odbacuje.</p>
${help('Svaka zona veže <b>sučelje</b> (fizički NIC ili VLAN na njemu) i <b>mrežu</b> (CIDR) uz <b>tip</b>: <code>lan</code> (povjerljivo), <code>dmz</code> (poluizolirano — serveri dostupni izvana), <code>guest</code> (izolirano) ili <code>wan</code> (nepovjerljivo, internet). Iz tipova se izvodi automatska međuzonska politika. <b>VLAN (802.1Q):</b> upiši VLAN ID (1-4094) da zona bude tagirani VLAN na istom fizičkom portu — više izoliranih zona na jednom kabelu (npr. DMZ=VLAN20, Gost=VLAN30 na enp2). Tada upiši i <b>adresu appliancea</b> na toj zoni (npr. 10.20.0.1/24) i klikni <b>Primijeni VLAN sučelja</b> (kreira <code>enpX.ID</code> preko netplana). Za iznimke dodaj <b>pravilo</b> s poljima <i>Iz zone / U zonu</i>. <b>DNS:</b> klikni <b>Primijeni DNS za zone</b> da klijenti u zoni smiju koristiti appliance kao DNS resolver (Unbound već sluša na svim sučeljima; dodaje se samo access-control za mrežu zone). Nakon promjene zona/pravila klikni <b>Primijeni firewall</b>.')}
<table><thead><tr><th>Naziv</th><th>Tip</th><th>Sučelje</th><th>Mreža / adresa</th><th>Akcije</th></tr></thead><tbody>${zoneRows}</tbody></table>
${(hasVlan||hasInternalZone)?`<div class="wizRow">${hasVlan?'<button id="znVlanApply">Primijeni VLAN sučelja (netplan)</button>':''}${hasInternalZone?'<button id="znDnsApply" class="ghost">Primijeni DNS za zone (Unbound)</button>':''}</div><div id="znVlanMsg" class="muted"></div>`:''}
<form id="znAdd" class="stack" style="display:none;border:1px solid var(--line,#394150);border-radius:8px;padding:.7rem .9rem;margin:.5rem 0">
<h4 id="znFormTitle" style="margin:.1rem 0 .3rem">Nova zona</h4>
<label>Naziv <input id="znName" placeholder="dmz" required></label>
<label>Tip <select id="znKind">${ZKINDS.map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}</select></label>
<label>Sučelje (fizički NIC / VLAN parent) <select id="znIf">${nics.length?nics.map(n=>`<option value="${e(n.name)}">${e(nlabel(n.name))}</option>`).join(''):'<option value="">(nema NIC-eva)</option>'}</select></label>
<label>VLAN ID (0 = bez VLAN-a) <input id="znVlan" type="number" min="0" max="4094" value="0"></label>
<label>Mreža (CIDR, prazno za WAN) <input id="znNet" placeholder="10.20.0.0/24"></label>
<label>Adresa appliancea na VLAN-u (CIDR) <input id="znAddr" placeholder="10.20.0.1/24"></label>
<div class="btnrow"><button type="submit">Dodaj zonu</button> <button type="button" id="znCancel" class="ghost">Odustani</button></div><div id="znMsg" class="muted"></div></form></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="test">
<div class="panel"><h3>Test pravila</h3>
<p class="muted">Upiši promet pa provjeri <b>koje pravilo</b> ga hvata i <b>prolazi li</b> (simulacija nad tvojim pravilima, ne dira kernel). Primijeni pravila da test odgovara živom stanju. Savjet: ikona ⚗ na retku pravila prednapuni ovaj obrazac.</p>
<form id="ruTest" class="stack">
<label>Izvor (IP) <input id="tsSrc" placeholder="192.168.30.10"></label>
<label>Odredište (IP) <input id="tsDst" placeholder="192.168.10.5"></label>
<label>Protokol <select id="tsProto"><option value="any">any</option><option value="tcp">tcp</option><option value="udp">udp</option></select></label>
<label>Odredišni port (0 = bilo koji) <input id="tsPort" type="number" min="0" max="65535" value="0"></label>
<div><button type="submit">Testiraj</button></div></form>
<div id="tsOut" style="margin-top:10px"></div></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="geo">
<div class="panel"><h3>Geo-blokada (po državi)</h3>
<p class="muted small">Blokiraj sav promet s IP raspona odabranih država (ISO-3166 alpha-2 kod, npr. <code>cn</code>, <code>ru</code>, <code>kp</code>). Liste se preuzimaju i učitavaju u firewall (drop na input i forward). Koristi kad napadi dolaze iz regije s kojom ne posluješ. Privatne mreže (LAN/mgmt) nisu u geo listama pa pristup ostaje.</p>
<div id="geoList" class="muted">Učitavanje…</div>
<div class="filterbar"><input id="geoInput" placeholder="npr. cn, ru, kp"><button type="button" id="geoApply">Primijeni geo-blokadu</button></div>
<div id="geoMsg" class="muted"></div></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="log">
<div class="panel"><h3>Firewall log (SNA)</h3>
<p class="muted small">Zapisi koje generiraju pravila s uključenim <b>LOG</b>-om, blokade i završna odbacivanja (netfilter LOG iz kernela) — vremenska crta <b>tko → kome</b>. Klikni <b>Blokiraj</b> da odmah zabraniš izvor.</p>
<div class="filterbar"><input id="fwlSearch" type="search" placeholder="Traži po IP-u / portu…"><button type="button" id="fwlReload" class="ghost">Osvježi</button></div>
<div id="fwlBody" class="muted">Učitavanje…</div></div></div>`;
wireTabs('fwTabs');
// Remember the open tab across the full-page reload that add/edit/apply trigger,
// so saving an alias or zone does not bounce the user back to Pravila.
document.querySelectorAll('#fwTabs .tab').forEach(t=>t.addEventListener('click',()=>{window.__fwTab=t.dataset.tab}));
if(window.__fwTab){const _tb=document.querySelector('#fwTabs .tab[data-tab="'+window.__fwTab+'"]');if(_tb)_tb.click()}
// Live per-rule traffic counters, mapped by rule name (best effort).
(async()=>{try{const cn=(await api('/api/firewall/counters')).counters||{};document.querySelectorAll('#ruTbody [data-cnt]').forEach(td=>{const c=cn[td.dataset.cnt];if(c)td.textContent=`${fmtBytes(c.bytes)} · ${(+c.packets).toLocaleString('hr-HR')} pkt`})}catch(e){}})();
const renderBlk=async()=>{const el=$('#blkList');if(!el)return;try{const ips=(await api('/api/firewall/blocklist')).ips||[];el.innerHTML=ips.length?`<table class="compact"><thead><tr><th>Blokirani IP</th><th></th></tr></thead><tbody>${ips.map(ip=>`<tr><td><b>${e(ip)}</b></td><td class="rowacts"><button class="blkDel danger" data-ip="${e(ip)}">Odblokiraj</button></td></tr>`).join('')}</tbody></table>`:'<p class="muted">Nema blokiranih IP adresa.</p>';el.querySelectorAll('.blkDel').forEach(b=>b.onclick=async()=>{try{await api('/api/firewall/unblock-ip',{method:'POST',body:JSON.stringify({ip:b.dataset.ip})});renderBlk()}catch(err){$('#blkMsg').textContent=err.message}})}catch(err){el.innerHTML='<span class="muted">—</span>'}};
renderBlk();
const blkAddBtn=$('#blkAdd');if(blkAddBtn)blkAddBtn.onclick=async()=>{const ip=$('#blkIP').value.trim();const m=$('#blkMsg');if(!isIPv4(ip)){m.textContent='Upiši ispravnu IPv4 adresu.';return}m.textContent='Blokiram…';try{await api('/api/firewall/block-ip',{method:'POST',body:JSON.stringify({ip})});$('#blkIP').value='';m.textContent='Blokirano: '+ip;renderBlk()}catch(err){m.textContent=err.message}};
let fwlData=[];
const renderFwl=()=>{const el=$('#fwlBody');if(!el)return;const q=($('#fwlSearch').value||'').toLowerCase().trim();
const rows=fwlData.filter(x=>!q||(x.src||'').includes(q)||(x.dst||'').includes(q)||(x.dport||'').includes(q)||(x.sport||'').includes(q)||(x.rule||'').toLowerCase().includes(q));
el.innerHTML=rows.length?`<table class="compact"><thead><tr><th>Vrijeme</th><th>Pravilo</th><th>Izvor</th><th>Odredište</th><th>Proto</th><th>Portovi</th><th></th></tr></thead><tbody>${rows.slice(0,300).map(x=>`<tr><td class="muted small">${e((x.time||'').replace('T',' ').slice(0,19))}</td><td><span class="chip chip-log">${e(x.rule||'')}</span></td><td>${e(x.src||'')}</td><td class="muted">${e(x.dst||'')}</td><td class="muted">${e(x.proto||'')}</td><td class="muted">${e(x.sport||'')}→${e(x.dport||'')}</td><td class="rowacts">${x.src?`<button class="fwlBlk danger" data-ip="${e(x.src)}">Blokiraj</button>`:''}</td></tr>`).join('')}</tbody></table>`:'<p class="muted">Nema zapisa (uključi LOG na pravilu ili pričekaj promet).</p>';
el.querySelectorAll('.fwlBlk').forEach(b=>b.onclick=async()=>{if(!confirm('Blokirati sav proslijeđeni promet s '+b.dataset.ip+'?'))return;b.disabled=true;b.textContent='…';try{await api('/api/firewall/block-ip',{method:'POST',body:JSON.stringify({ip:b.dataset.ip})});b.textContent='Blokiran';renderBlk()}catch(err){b.disabled=false;b.textContent='Blokiraj';alert(err.message)}})};
const loadFwl=async()=>{const el=$('#fwlBody');if(el)el.innerHTML='<span class="muted">Učitavanje…</span>';try{fwlData=(await api('/api/firewall/log')).entries||[]}catch(err){fwlData=[]}renderFwl()};
loadFwl();const fwlS=$('#fwlSearch');if(fwlS)fwlS.oninput=renderFwl;const fwlR=$('#fwlReload');if(fwlR)fwlR.onclick=loadFwl;
let geoCodes=[];
const geoSubmit=async(list)=>{const m=$('#geoMsg');m.textContent='Preuzimam liste i primjenjujem…';try{const r=await api('/api/geoip/apply',{method:'POST',body:JSON.stringify({countries:list})});m.textContent=`Primijenjeno (${r.cidrs||0} raspona).`;renderGeo()}catch(err){m.textContent=err.message}};
const renderGeo=async()=>{const el=$('#geoList');if(!el)return;try{const g=await api('/api/geoip');geoCodes=g.countries||[];const counts=g.counts||{};
el.innerHTML=geoCodes.length?`<table class="compact"><thead><tr><th>Država (ISO)</th><th>CIDR-ova</th><th></th></tr></thead><tbody>${geoCodes.map(cc=>`<tr><td><b>${e(cc.toUpperCase())}</b></td><td class="muted">${counts[cc]||0}</td><td class="rowacts"><button class="geoDel danger" data-cc="${e(cc)}">Ukloni</button></td></tr>`).join('')}</tbody></table>`:'<p class="muted">Nijedna država nije blokirana.</p>';
el.querySelectorAll('.geoDel').forEach(b=>b.onclick=()=>geoSubmit(geoCodes.filter(x=>x!==b.dataset.cc)))}catch(err){el.innerHTML='<span class="muted">—</span>'}};
renderGeo();
const geoApplyBtn=$('#geoApply');if(geoApplyBtn)geoApplyBtn.onclick=()=>{const add=($('#geoInput').value||'').split(/[\s,]+/).map(x=>x.trim().toLowerCase()).filter(Boolean);const merged=[...new Set([...geoCodes,...add])];$('#geoInput').value='';geoSubmit(merged)};
if(f.pending){$('#fwConfirm').onclick=async()=>{try{await api('/api/gateway/confirm',{method:'POST',body:'{}'});fwRulesPage()}catch(err){alert(err.message)}};$('#fwRollback').onclick=async()=>{try{await api('/api/gateway/rollback',{method:'POST',body:'{}'});fwRulesPage()}catch(err){alert(err.message)}}}
$('#fwApply').onclick=async()=>{if(!confirm('Primijeniti firewall? Bez potvrde u 120 s vraća se stara konfiguracija.'))return;const m=$('#fwMsg');m.textContent='Primjena…';try{await api('/api/firewall/apply',{method:'POST',body:'{}'});fwRulesPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.alDel').forEach(el=>el.onclick=async()=>{const list=aliases.filter((_,j)=>j!==+el.dataset.i);try{await putAliases(list);fwRulesPage()}catch(err){alert(err.message)}});
let alEdit=-1;const alAddBtn=$('#alAddBtn');
const alReset=()=>{alEdit=-1;$('#alAdd').reset();if(alAddBtn)alAddBtn.textContent='Dodaj alias';$('#alMsg').textContent=''};
const alDrawer=makeDrawer({form:'alAdd',title:'alFormTitle',newBtn:'alNew',cancel:'alCancel',addTitle:'Novi alias',reset:alReset,focus:'alName'});
document.querySelectorAll('.alEdit').forEach(el=>el.onclick=()=>{const a=aliases[+el.dataset.i];alEdit=+el.dataset.i;$('#alName').value=a.name||'';$('#alType').value=a.type||'host';$('#alVals').value=(a.values||[]).join(', ');if(alAddBtn)alAddBtn.textContent='Spremi izmjene';$('#alMsg').textContent='';alDrawer.edit('Uredi alias — '+(a.name||''))});
$('#alAdd').onsubmit=async ev=>{ev.preventDefault();const m=$('#alMsg');m.textContent='';const name=$('#alName').value.trim(),type=$('#alType').value,vals=$('#alVals').value.split(',').map(x=>x.trim()).filter(Boolean);
if(!/^[a-z][a-z0-9_]{0,30}$/.test(name)){m.textContent='Naziv: počni slovom, dozvoljeno a-z 0-9 _ (bez crtice).';return}
if(!vals.length){m.textContent='Upiši barem jednu vrijednost.';return}
for(const v of vals){const okv=type==='host'?isIPv4(v):type==='network'?isCIDR(v):isRange(v);if(!okv){m.textContent='Neispravna vrijednost za tip '+type+': '+v;return}}
if(aliases.some((a,j)=>a.name===name&&j!==alEdit)){m.textContent='Alias s tim imenom već postoji.';return}
const list=aliases.slice();if(alEdit>=0){list[alEdit]={name,type,values:vals}}else{list.push({name,type,values:vals})}
try{await putAliases(list);fwRulesPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.ruDel').forEach(el=>el.onclick=async()=>{const list=rules.filter((_,j)=>j!==+el.dataset.i);try{await putRules(list);fwRulesPage()}catch(err){alert(err.message)}});
let ruEdit=-1;const ruAddBtn=$('#ruAddBtn');
const ruReset=()=>{ruEdit=-1;$('#ruAdd').reset();$('#ruEnabled').checked=true;if(ruAddBtn)ruAddBtn.textContent='Dodaj pravilo';$('#ruMsg').textContent=''};
const ruDrawer=makeDrawer({form:'ruAdd',title:'ruFormTitle',newBtn:'ruNew',cancel:'ruCancel',addTitle:'Novo pravilo',reset:ruReset,focus:'ruName'});
document.querySelectorAll('.ruEdit').forEach(el=>el.onclick=()=>{const r=rules[+el.dataset.i];ruEdit=+el.dataset.i;
$('#ruName').value=r.name||'';$('#ruAction').value=r.action||'accept';$('#ruProto').value=r.proto||'any';$('#ruSrc').value=r.srcAlias||'';$('#ruDst').value=r.dstAlias||'';$('#ruPort').value=r.dstPort||0;$('#ruFromZone').value=r.fromZone||'';$('#ruToZone').value=r.toZone||'';$('#ruCat').value=r.category||'';$('#ruLog').checked=!!r.log;$('#ruEnabled').checked=r.enabled!==false;
const sc=r.schedule||{};document.querySelectorAll('.ruDay').forEach(cb=>{cb.checked=(sc.days||[]).includes(+cb.value)});$('#ruSchStart').value=sc.start||'';$('#ruSchEnd').value=sc.end||'';
if(ruAddBtn)ruAddBtn.textContent='Spremi izmjene';$('#ruMsg').textContent='';ruDrawer.edit(`Uredi pravilo #${ruEdit+1} — ${r.name||''}`)});
const move=async(i,d)=>{const j=i+d;if(j<0||j>=rules.length)return;const list=rules.slice();const t=list[i];list[i]=list[j];list[j]=t;try{await putRules(list);fwRulesPage()}catch(err){alert(err.message)}};
document.querySelectorAll('.ruUp').forEach(el=>el.onclick=()=>move(+el.dataset.i,-1));
document.querySelectorAll('.ruDown').forEach(el=>el.onclick=()=>move(+el.dataset.i,1));
const applyRuFilter=()=>{const q=($('#ruSearch').value||'').toLowerCase().trim();const cat=$('#ruFilter').value,act=$('#ruFAction').value,st=$('#ruFStatus').value;
document.querySelectorAll('#ruTbody tr.expandable').forEach(tr=>{const ok=(cat==='__all'||(tr.dataset.cat||'')===cat)&&(act==='__all'||tr.dataset.action===act)&&(st==='__all'||tr.dataset.enabled===st)&&(!q||(tr.dataset.name||'').includes(q));
tr.style.display=ok?'':'none';const d=document.querySelector(`#ruTbody tr[data-detail="${tr.dataset.i}"]`);if(d)d.style.display=ok?'':'none'})};
['ruSearch','ruFilter','ruFAction','ruFStatus'].forEach(id=>{const el=$('#'+id);if(el){el.oninput=applyRuFilter;el.onchange=applyRuFilter}});
$('#ruFReset').onclick=()=>{$('#ruSearch').value='';$('#ruFilter').value='__all';$('#ruFAction').value='__all';$('#ruFStatus').value='__all';applyRuFilter()};
const fwNatEdit=$('#fwNatEdit');if(fwNatEdit)fwNatEdit.onclick=()=>openModule('gateway');
document.querySelectorAll('#ruTbody tr.expandable').forEach(tr=>tr.onclick=ev=>{if(ev.target.closest('.iconbtn'))return;tr.classList.toggle('open');const d=document.querySelector(`#ruTbody tr[data-detail="${tr.dataset.i}"]`);if(d)d.classList.toggle('hidden')});
document.querySelectorAll('.ruTestBtn').forEach(el=>el.onclick=()=>{const r=rules[+el.dataset.i];$('#tsSrc').value=r.srcAlias?firstVal(r.srcAlias):'';$('#tsDst').value=r.dstAlias?firstVal(r.dstAlias):'';$('#tsProto').value=r.proto||'any';$('#tsPort').value=r.dstPort||0;const tb=document.querySelector('#fwTabs .tab[data-tab="test"]');if(tb)tb.click();$('#tsSrc').focus()});
$('#ruAdd').onsubmit=async ev=>{ev.preventDefault();const m=$('#ruMsg');m.textContent='';const name=$('#ruName').value.trim(),proto=$('#ruProto').value,port=parseInt($('#ruPort').value,10)||0;
if(!/^[A-Za-z0-9 ._-]{1,40}$/.test(name)){m.textContent='Naziv pravila: 1-40 znakova (slova, brojke, razmak . _ -).';return}
if(port&&proto==='any'){m.textContent='Za odredišni port odaberi tcp ili udp.';return}
if(rules.some((r,j)=>r.name===name&&j!==ruEdit)){m.textContent='Pravilo s tim imenom već postoji.';return}
const days=Array.from(document.querySelectorAll('.ruDay:checked')).map(cb=>+cb.value);const st=$('#ruSchStart').value,en=$('#ruSchEnd').value;
if((st&&!en)||(en&&!st)){m.textContent='Za vremenski raspon ispuni oba polja (Od i Do) ili nijedno.';return}
const rule={name,action:$('#ruAction').value,proto,srcAlias:$('#ruSrc').value,dstAlias:$('#ruDst').value,dstPort:port,fromZone:$('#ruFromZone').value,toZone:$('#ruToZone').value,category:$('#ruCat').value,log:$('#ruLog').checked,enabled:$('#ruEnabled').checked};
if(days.length||st||en){rule.schedule={days,start:st,end:en}}
const list=rules.slice();if(ruEdit>=0){list[ruEdit]=rule}else{list.push(rule)}
try{await putRules(list);fwRulesPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.znDel').forEach(el=>el.onclick=async()=>{const list=zones.filter((_,j)=>j!==+el.dataset.i);try{await putZones(list);fwRulesPage()}catch(err){alert(err.message)}});
document.querySelectorAll('.znDhcp').forEach(el=>el.onclick=()=>{const z=zones[+el.dataset.i];const ifn=z.vlanId?z.interface+'.'+z.vlanId:z.interface;const router=z.address?z.address.split('/')[0]:'';window.__zoneDhcp={name:z.name,subnet:z.network,iface:ifn,router};openModule('dhcp')});
const znVlanBtn=$('#znVlanApply');if(znVlanBtn)znVlanBtn.onclick=async()=>{if(!confirm('Primijeniti VLAN sučelja? Ovo piše netplan i radi netplan apply (kreira/mijenja VLAN pod-sučelja).'))return;const m=$('#znVlanMsg');znVlanBtn.disabled=true;m.textContent='Primjena netplana…';try{const r=await api('/api/firewall/zones/apply-vlans',{method:'POST',body:'{}'});m.textContent=`VLAN sučelja primijenjena (${r.vlans}).`}catch(err){m.textContent=err.message}finally{znVlanBtn.disabled=false}};
const znDnsBtn=$('#znDnsApply');if(znDnsBtn)znDnsBtn.onclick=async()=>{const m=$('#znVlanMsg');znDnsBtn.disabled=true;m.textContent='Primjena DNS pristupa…';try{const r=await api('/api/firewall/zones/apply-dns',{method:'POST',body:'{}'});m.textContent=`DNS pristup primijenjen za ${r.zones} zona (Unbound sluša na svim sučeljima).`}catch(err){m.textContent=err.message}finally{znDnsBtn.disabled=false}};
$('#znAdd').onsubmit=async ev=>{ev.preventDefault();const m=$('#znMsg');m.textContent='';const name=$('#znName').value.trim(),kind=$('#znKind').value,iface=$('#znIf').value,vlan=parseInt($('#znVlan').value,10)||0,net=$('#znNet').value.trim(),addr=$('#znAddr').value.trim();
if(!/^[a-z][a-z0-9_-]{0,20}$/.test(name)){m.textContent='Naziv zone: počni slovom (a-z 0-9 _ -).';return}
if(!iface){m.textContent='Odaberi sučelje.';return}
if(vlan<0||vlan>4094){m.textContent='VLAN ID mora biti 0 (bez) ili 1-4094.';return}
if(kind!=='wan'&&!isCIDR(net)){m.textContent='Mreža mora biti CIDR (npr. 10.20.0.0/24).';return}
if(vlan>0&&!isCIDR(addr)){m.textContent='Za VLAN upiši adresu appliancea (CIDR, npr. 10.20.0.1/24).';return}
const ifn=vlan>0?iface+'.'+vlan:iface;
if(zones.some(z=>z.name===name)){m.textContent='Zona s tim imenom već postoji.';return}
if(zones.some(z=>(z.vlanId?z.interface+'.'+z.vlanId:z.interface)===ifn)){m.textContent='To je sučelje ('+ifn+') već dodijeljeno drugoj zoni.';return}
const zone={name,kind,interface:iface,network:net};if(vlan>0){zone.vlanId=vlan;zone.address=addr}
try{await putZones(zones.concat([zone]));fwRulesPage()}catch(err){m.textContent=err.message}};
makeDrawer({form:'znAdd',title:'znFormTitle',newBtn:'znNew',cancel:'znCancel',addTitle:'Nova zona',reset:()=>{$('#znAdd').reset();$('#znMsg').textContent=''},focus:'znName'});
$('#ruTest').onsubmit=async ev=>{ev.preventDefault();const o=$('#tsOut');const src=$('#tsSrc').value.trim(),dst=$('#tsDst').value.trim();
if(src&&!isIPv4(src)){o.innerHTML='<span class="error">Izvor mora biti IPv4 adresa.</span>';return}
if(dst&&!isIPv4(dst)){o.innerHTML='<span class="error">Odredište mora biti IPv4 adresa.</span>';return}
o.textContent='Testiram…';try{const rr=await api('/api/firewall/test',{method:'POST',body:JSON.stringify({src,dst,proto:$('#tsProto').value,dstPort:parseInt($('#tsPort').value,10)||0})});const act=rr.action;const cls=act==='accept'?'st-healthy':(act==='drop'||act==='reject')?'st-error':'st-unknown';o.innerHTML=`<span class="status ${cls}">${escapeHtml(act)}</span> ${rr.matched?'— odgovara pravilo <b>#'+rr.ruleIndex+' '+escapeHtml(rr.ruleName)+'</b>':'— nijedno custom pravilo, vrijedi zadana politika'}<p class="muted" style="margin:8px 0 0">${escapeHtml(rr.reason)}</p>`}catch(err){o.innerHTML='<span class="error">'+escapeHtml(err.message)+'</span>'}}}
function sevClass(s){return({critical:'st-error',warning:'st-unknown',info:'st-muted'})[s]||''}
async function conflictsPage(){const d=await api('/api/conflicts');const list=d.conflicts||[];const e=escapeHtml;const ch=d.checked||{};
const rows=list.length?list.map(c=>`<tr><td><span class="status ${sevClass(c.severity)}">${e(c.severity)}</span></td><td class="muted">${e(c.kind)}</td><td>${e(c.message)}</td></tr>`).join(''):'<tr><td colspan="3" class="st-healthy">Nema konflikata. ✓</td></tr>';
$('#content').innerHTML=`<div class="panel"><h2>Pregled konflikata</h2>
<p class="muted">Provjereno: ${ch.subnets||0} subneta, ${ch.reservations||0} rezervacija. Traže se preklapanja mreža/poolova, duplikati MAC/IP, rezervacije izvan subneta i proturječja s blokom.</p>
${help('Ova stranica čita živu Kea konfiguraciju i rezervacije te javlja probleme: <b>critical</b> = preklapanje subneta ili dupli MAC/IP (DHCP se ponaša nepredvidljivo — riješi odmah); <b>warning</b> = pool izvan subneta, preklapajući poolovi ili rezervacija izvan svog subneta; <b>info</b> = rezervacija unutar dinamičkog poola (radi, ali bolje izmjesti izvan poola). Popravi u <b>DHCP</b> modulu pa osvježi.')}
<div class="wizRow"><button id="cfRefresh">Osvježi</button></div>
<table><thead><tr><th>Ozbiljnost</th><th>Vrsta</th><th>Opis</th></tr></thead><tbody>${rows}</tbody></table></div>`;
$('#cfRefresh').onclick=conflictsPage}
async function configVersionsPage(){const e=escapeHtml;const d=await api('/api/config/versions').catch(err=>({versions:[],err:err.message}));const vs=d.versions||[];
const rows=vs.length?vs.map(v=>`<tr><td class="muted small">${e(new Date(v.time).toLocaleString('hr-HR'))}</td><td>${(v.changed||[]).length?(v.changed||[]).map(c=>`<span class="chip chip-zone">${e(c)}</span>`).join(' '):'<span class="muted">—</span>'}</td><td class="muted small">${e(v.lastAction||'')}</td><td class="rowacts"><button class="cvView ghost" data-id="${e(v.id)}">Pregled</button> <button class="cvRestore danger" data-id="${e(v.id)}">Vrati</button></td></tr>`).join(''):'<tr><td colspan="4" class="muted">Nema snimaka konfiguracije.</td></tr>';
$('#content').innerHTML=`<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h2 style="margin:0">Verzije konfiguracije</h2><button type="button" id="cvCheckpoint">+ Kontrolna točka</button></div>
${help('Svaka promjena konfiguracije (Vatrozid, DHCP intent, DNS split-horizon, WAN, VPN…) automatski se snima kao <b>verzija</b>; promjene samo u audit logu se ne broje. Čuva se zadnjih '+(d.max||40)+'. <b>Vrati</b> zamijeni trenutnu konfiguraciju odabranom snimkom (audit log i status servisa ostaju), a zatim <b>ponovno primijeni</b> pogođene module (Vatrozid/DHCP/WAN…) da promjene stupe na snagu na živim servisima. <b>Kontrolna točka</b> ručno snimi trenutno stanje prije rizične izmjene. Vraćanje smije samo administrator.')}
${d.err?`<p class="error">${e(d.err)}</p>`:''}
<table><thead><tr><th>Vrijeme</th><th>Promijenjeno</th><th>Zadnja akcija</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
<div id="cvDetail"></div>`;
$('#cvCheckpoint').onclick=async()=>{const label=prompt('Naziv kontrolne točke (opcionalno):','');if(label===null)return;try{await api('/api/config/checkpoint',{method:'POST',body:JSON.stringify({label:label.trim()})});configVersionsPage()}catch(err){alert(err.message)}};
document.querySelectorAll('.cvView').forEach(el=>el.onclick=async()=>{try{const v=await api('/api/config/versions/'+encodeURIComponent(el.dataset.id));$('#cvDetail').innerHTML=`<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h3 style="margin:0">Snimka — ${e(new Date(v.time).toLocaleString('hr-HR'))}</h3><button type="button" class="ghost" id="cvClose">Zatvori</button></div><p class="muted small">${(v.changed||[]).length?'Promijenjeno: '+e((v.changed||[]).join(', ')):'—'}</p><pre class="muted small" style="white-space:pre-wrap;max-height:460px;overflow:auto;margin:.3rem 0 0">${e(JSON.stringify(v.state,null,2))}</pre></div>`;$('#cvClose').onclick=()=>{$('#cvDetail').innerHTML=''};$('#cvDetail').scrollIntoView({block:'nearest'})}catch(err){alert(err.message)}});
document.querySelectorAll('.cvRestore').forEach(el=>el.onclick=async()=>{if(!confirm('Vratiti konfiguraciju na ovu snimku?\nTrenutna konfiguracija se zamjenjuje (audit log ostaje). Nakon toga MORAŠ ponovno primijeniti pogođene module da promjene stupe na snagu.'))return;try{const r=await api('/api/config/versions/'+encodeURIComponent(el.dataset.id)+'/restore',{method:'POST',body:'{}'});alert((r.message||'Vraćeno.')+((r.changed&&r.changed.length)?'\n\nPromijenjene sekcije: '+r.changed.join(', '):''));configVersionsPage()}catch(err){alert(err.message)}})}
async function diagPage(){const e=escapeHtml;
const [logR,cntR,blkR,fwR,nicsR]=await Promise.all([
  api('/api/firewall/log').catch(()=>({entries:[]})),
  api('/api/firewall/counters').catch(()=>({})),
  api('/api/firewall/blocklist').catch(()=>({ips:[]})),
  api('/api/firewall').catch(()=>({rules:[]})),
  api('/api/interfaces').catch(()=>[])]);
const nics=Array.isArray(nicsR)?nicsR:[];
const entries=(logR.entries||[]).slice();
const rules=fwR.rules||[];const ruleByName=Object.fromEntries(rules.map(r=>[r.name,r]));
const blocked=new Set(blkR.ips||[]);
const d=cntR.drops||{};const fd=d.forward||{},idc=d.input||{};
const tile=(label,val,sub)=>`<div style="flex:1 1 130px;min-width:130px;border:1px solid var(--line,#394150);border-radius:10px;padding:.6rem .8rem"><div class="muted small" style="text-transform:uppercase;letter-spacing:.08em">${label}</div><div style="font-size:1.5rem;font-weight:700;font-variant-numeric:tabular-nums">${val}</div><div class="muted small">${sub||''}</div></div>`;
const bySrc={};entries.forEach(x=>{const sc=x.src||'?';const g=bySrc[sc]||(bySrc[sc]={src:sc,n:0,last:x,rules:{},dsts:{}});g.n++;g.rules[x.rule||'—']=1;g.dsts[(x.dst||'')+(x.dport?':'+x.dport:'')]=1;if((x.time||'')>(g.last.time||''))g.last=x});
const srcList=Object.values(bySrc).sort((a,b)=>b.n-a.n);
const reason=x=>{if(!x.rule)return 'završni drop (default policy)';const r=ruleByName[x.rule];return r?('pravilo „'+x.rule+'“ → '+(r.action||'?')):('LOG „'+x.rule+'“')};
const empty=!entries.length;
const actCl=a=>a==='accept'?'st-healthy':(a==='drop'||a==='reject')?'st-error':'';
const cnts=cntR.counters||{};const talkers=Object.entries(cnts).map(([name,c])=>({name,packets:+(c&&c.packets)||0,bytes:+(c&&c.bytes)||0})).filter(t=>t.bytes>0||t.packets>0).sort((a,b)=>b.bytes-a.bytes);const talkMax=talkers.length?(talkers[0].bytes||1):1;
$('#content').innerHTML=`<div class="panel"><h2>Dijagnostika — zašto paket pada</h2>
${help('<b>Vođeni put</b> od simptoma do uzroka: <b>1. Log</b> — koji je promet odbačen/logiran. <b>2. Razlog</b> — koje ga pravilo hvata ili je „završni drop“. <b>3. Pravilo</b> — otvori ga u Vatrozidu, provjeri redoslijed i akciju. <b>4. Akcija</b> — blokiraj izvor odmah ili ispravi/dodaj pravilo. <br><br>Koristi se <b>firewall log</b> (pravila s uključenim <b>LOG</b>-om + završna odbacivanja). Živi <b>packet capture</b> (tcpdump po filteru) je planirani dublji korak.')}
<div style="display:flex;gap:.7rem;flex-wrap:wrap;margin:.4rem 0 .2rem">
${tile('Forward drop',(+(fd.packets||0)).toLocaleString('hr-HR'),fd.bytes?fmtBytes(fd.bytes):'paketa')}
${tile('Input drop',(+(idc.packets||0)).toLocaleString('hr-HR'),idc.bytes?fmtBytes(idc.bytes):'paketa')}
${tile('Izvora u logu',srcList.length,'različitih IP-ova')}
${tile('Blokirano',blocked.size,'IP na blocklisti')}
</div></div>
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h3 style="margin:0">Izvori odbačenog prometa (${srcList.length})</h3><button type="button" id="diagReload" class="ghost">Osvježi</button></div>
${empty?'<p class="muted">Nema zapisa u firewall logu. Uključi <b>LOG</b> na pravilu (Vatrozid → pravilo → „Logiraj promet“) ili pričekaj da završni drop uhvati promet, pa osvježi.</p>':`<table><thead><tr><th>Izvor</th><th>Pogodaka</th><th>Zadnji razlog</th><th>Primjeri odredišta</th><th></th></tr></thead><tbody>${srcList.map(g=>`<tr><td><b>${e(g.src)}</b>${blocked.has(g.src)?' <span class="badge">blokiran</span>':''}</td><td class="muted">${g.n}</td><td class="muted small">${e(reason(g.last))}</td><td class="muted small">${e(Object.keys(g.dsts).slice(0,3).join(', '))}${Object.keys(g.dsts).length>3?'…':''}</td><td class="rowacts"><button class="dgInv ghost" data-s="${e(g.src)}">Istraži</button> ${blocked.has(g.src)?'':`<button class="dgBlk danger" data-s="${e(g.src)}">Blokiraj</button>`}</td></tr>`).join('')}</tbody></table>`}</div>
<div id="diagDetail"></div>
<div class="panel"><h3>Cijeli firewall log (${entries.length})</h3>
${empty?'':searchBar('dgSearch','Traži po IP / portu / pravilu…')}
${empty?'':`<table><thead><tr><th>Vrijeme</th><th>Pravilo/razlog</th><th>Izvor</th><th>Odredište</th><th>Proto</th><th>Portovi</th></tr></thead><tbody id="dgLogTbody">${entries.slice(0,300).map(x=>`<tr><td class="muted small">${e((x.time||'').replace('T',' ').slice(0,19))}</td><td>${x.rule?`<span class="chip chip-log">${e(x.rule)}</span>`:'<span class="muted">završni drop</span>'}</td><td>${e(x.src||'')}</td><td class="muted">${e(x.dst||'')}</td><td class="muted">${e(x.proto||'')}</td><td class="muted">${e(x.sport||'')}→${e(x.dport||'')}</td></tr>`).join('')}</tbody></table>`}</div>
<div class="panel"><h3>Najprometnija pravila <span class="badge">nft counteri</span></h3>
<p class="muted small">Pravila firewalla poredana po prometu koji su propustila ili odbila — živi nft <b>byte/packet</b> counteri (kumulativno od zadnje primjene rulesetа). Pokazuje kuda ide najviše prometa i koje ga pravilo hvata.</p>
${talkers.length?`<table><thead><tr><th>#</th><th>Pravilo</th><th>Akcija</th><th>Promet</th><th>Paketi</th><th>Udio</th></tr></thead><tbody>${talkers.slice(0,15).map((t,i)=>{const r=ruleByName[t.name];const pct=Math.round(100*t.bytes/talkMax);return `<tr><td class="muted">${i+1}</td><td><b>${e(t.name)}</b></td><td>${r?`<span class="status ${actCl(r.action)}">${e(r.action||'')}</span>`:'<span class="muted">—</span>'}</td><td style="font-variant-numeric:tabular-nums">${fmtBytes(t.bytes)}</td><td class="muted" style="font-variant-numeric:tabular-nums">${t.packets.toLocaleString('hr-HR')}</td><td style="min-width:120px">${barPct(pct)}</td></tr>`}).join('')}</tbody></table><p class="muted small">Uz to: <b>Forward drop</b> i <b>Input drop</b> gore su završni „catch-all“ counteri. Counteri se resetiraju na svaku primjenu firewalla.</p>`:'<p class="muted">Nema countera s prometom — firewall možda nije primijenjen ili kroz custom pravila još nije prošao promet.</p>'}</div>
<div class="panel"><h3>Packet capture (uživo) <span class="badge">napredno</span></h3>
<p class="muted small">Kratki, ograničeni snimak <b>zaglavlja</b> paketa (bez sadržaja, snaplen 96 B, ne-promiskuitetno) na odabranom sučelju — vidiš tko s kim priča i prolazi li promet. Snima <b>do 500 paketa ili 25 s</b>, što prije dođe. Za dublju analizu od loga.</p>
<div class="filterbar"><select id="capIf">${nics.map(n=>`<option value="${e(n.name)}">${e(nlabel(n.name))}</option>`).join('')||'<option value="">(nema sučelja)</option>'}</select><select id="capProto"><option value="any">svi protokoli</option><option value="tcp">tcp</option><option value="udp">udp</option><option value="icmp">icmp</option></select><input id="capHost" placeholder="host IP (opc.)" style="max-width:150px"><input id="capPort" type="number" min="1" max="65535" placeholder="port (opc.)" style="max-width:110px"><input id="capCount" type="number" min="1" max="500" value="50" title="max paketa" style="max-width:90px"><button type="button" id="capRun">Snimaj</button></div>
<pre id="capOut" class="muted" style="white-space:pre-wrap;max-height:340px;overflow:auto;margin:.4rem 0 0"></pre></div>
<div class="panel"><h3>Aktivne veze (conntrack)</h3>
<p class="muted small">Trenutni snimak tablice praćenja veza (nf_conntrack) — tko s kim ima otvorenu vezu, protokol, stanje i smjer. Read-only; prikazano do 500 redaka.</p>
<div class="filterbar">${searchBar('ctSearch','Traži po IP / portu / stanju…')}<span id="ctSummary" class="muted small"></span><span style="flex:1"></span><button type="button" id="ctReload" class="ghost">Osvježi</button></div>
<table><thead><tr><th>Proto</th><th>Izvor</th><th>Odredište</th><th>Stanje</th><th>Zastavice</th><th class="muted">Timeout</th></tr></thead><tbody id="ctTbody"><tr><td colspan="6" class="muted">Učitavam…</td></tr></tbody></table></div>`;
tableSearch('dgSearch','dgLogTbody');
const ctGet=(s,k)=>{const m=s.match(new RegExp('(?:^|\\s)'+k+'=([^\\s]+)'));return m?m[1]:''};
const parseCt=(out)=>{const res=[];(out||'').split('\n').forEach(ln=>{const s=ln.trim();if(!s)return;const t=s.split(/\s+/);if(t.length<3)return;res.push({proto:t[0],timeout:/^\d+$/.test(t[2])?t[2]:'',state:(t.find(x=>/^[A-Z][A-Z_]+$/.test(x))||''),flags:(s.match(/\[[A-Z]+\]/g)||[]).join(' '),src:ctGet(s,'src'),dst:ctGet(s,'dst'),sport:ctGet(s,'sport'),dport:ctGet(s,'dport')})});return res};
const loadCt=async()=>{const tb=$('#ctTbody'),sm=$('#ctSummary');if(!tb)return;tb.innerHTML='<tr><td colspan="6" class="muted">Učitavam…</td></tr>';try{const r=await api('/api/diag/conntrack?limit=500');const rows=parseCt(r.output);if(sm)sm.textContent=`Aktivnih veza: ${(r.count||0).toLocaleString('hr-HR')}${r.max?` / ${r.max.toLocaleString('hr-HR')}`:''}${rows.length?` · prikazano ${rows.length}`:''}`;tb.innerHTML=rows.length?rows.map(x=>`<tr><td>${e(x.proto)}</td><td>${e(x.src)}${x.sport?':'+e(x.sport):''}</td><td class="muted">${e(x.dst)}${x.dport?':'+e(x.dport):''}</td><td>${x.state?`<span class="badge">${e(x.state)}</span>`:'<span class="muted">—</span>'}</td><td class="muted small">${e(x.flags)}</td><td class="muted small">${x.timeout?e(x.timeout)+' s':''}</td></tr>`).join(''):'<tr><td colspan="6" class="muted">Nema aktivnih veza (ili conntrack nije dostupan).</td></tr>'}catch(err){tb.innerHTML=`<tr><td colspan="6" class="muted">${e(err.message)}</td></tr>`}};
tableSearch('ctSearch','ctTbody');
const ctReload=$('#ctReload');if(ctReload)ctReload.onclick=loadCt;
loadCt();
const capRun=$('#capRun');if(capRun)capRun.onclick=async()=>{const out=$('#capOut');const iface=$('#capIf').value;if(!iface){out.textContent='Odaberi sučelje.';return}const body={interface:iface,proto:$('#capProto').value,host:$('#capHost').value.trim(),port:parseInt($('#capPort').value,10)||0,count:parseInt($('#capCount').value,10)||50};capRun.disabled=true;out.textContent=`Snimam na ${nlabel(iface)}… (do ${body.count} paketa / 25 s)`;try{const rr=await api('/api/diag/capture',{method:'POST',body:JSON.stringify(body)});out.textContent=(rr.output&&rr.output.trim())?rr.output:'(nijedan paket nije uhvaćen u zadanom vremenu/filteru)'}catch(err){out.textContent=err.message}finally{capRun.disabled=false}};
$('#diagReload').onclick=diagPage;
document.querySelectorAll('.dgBlk').forEach(b=>b.onclick=async()=>{if(!confirm('Blokirati sav proslijeđeni promet s '+b.dataset.s+'?'))return;try{await api('/api/firewall/block-ip',{method:'POST',body:JSON.stringify({ip:b.dataset.s})});diagPage()}catch(err){alert(err.message)}});
document.querySelectorAll('.dgInv').forEach(b=>b.onclick=()=>{const src=b.dataset.s;const rows=entries.filter(x=>(x.src||'')===src);const g=bySrc[src];
const ruleNames=Object.keys(g.rules).filter(r=>r!=='—');
$('#diagDetail').innerHTML=`<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h3 style="margin:0">Istraga: ${e(src)} <span class="muted small">(${rows.length} zapisa)</span></h3><button type="button" class="ghost" id="dgClose">Zatvori</button></div>
<p class="muted small">Ovaj izvor je uhvaćen ${ruleNames.length?('pravilima: '+e(ruleNames.join(', '))):'završnim dropom (nijedno pravilo ga eksplicitno ne propušta)'}. ${ruleNames.length?'Otvori Vatrozid da provjeriš redoslijed i akciju pravila.':'Ako bi ovaj promet trebao proći, dodaj accept pravilo u Vatrozidu; ako ne — blokiraj izvor.'}</p>
<table class="compact"><thead><tr><th>Vrijeme</th><th>Odredište</th><th>Proto/port</th><th>Pravilo</th></tr></thead><tbody>${rows.slice(0,100).map(x=>`<tr><td class="muted small">${e((x.time||'').replace('T',' ').slice(0,19))}</td><td>${e(x.dst||'')}</td><td class="muted">${e(x.proto||'')}${x.dport?':'+e(x.dport):''}</td><td>${x.rule?`<span class="chip chip-log">${e(x.rule)}</span>`:'<span class="muted">završni drop</span>'}</td></tr>`).join('')}</tbody></table>
<div class="btnrow"><button type="button" class="ghost" id="dgToFw">Otvori Vatrozid (pravila)</button> ${blocked.has(src)?'<span class="badge">već blokiran</span>':`<button type="button" class="danger" id="dgBlk2">Blokiraj ${e(src)}</button>`}</div></div>`;
$('#dgClose').onclick=()=>{$('#diagDetail').innerHTML=''};
$('#dgToFw').onclick=()=>{window.__fwTab='pravila';openModule('fwrules')};
const b2=$('#dgBlk2');if(b2)b2.onclick=async()=>{if(!confirm('Blokirati '+src+'?'))return;try{await api('/api/firewall/block-ip',{method:'POST',body:JSON.stringify({ip:src})});diagPage()}catch(err){alert(err.message)}};
$('#diagDetail').scrollIntoView({block:'nearest'})});}
async function siemPage(){const s=await api('/api/siem');const e=escapeHtml;
$('#content').innerHTML=`<div class="panel"><h2>SIEM / prosljeđivanje logova ${s.enabled?'<span class="badge">aktivno</span>':''}</h2>
<p class="muted">Prosljeđuje audit i sigurnosne događaje na vanjski SIEM/kolektor u realnom vremenu (best-effort, ne blokira rad).</p>
${help('Odaberi <b>protokol</b> (UDP = klasični syslog; TCP/TLS za pouzdanost/šifriranje), <b>host</b> i <b>port</b> kolektora, te <b>format</b>: <b>RFC5424</b> (syslog), <b>CEF</b> (ArcSight/Sentinel/QRadar) ili <b>JSON</b>. <b>Prag ozbiljnosti</b> određuje od koje razine se šalje (npr. warning → warning/error/critical/security). Za TLS na samopotpisani kolektor uključi „prihvati samopotpisani". <b>Test</b> spremi postavke i pošalje probni događaj.')}
<form id="siemForm" class="stack">
<label><input id="siEn" type="checkbox" ${s.enabled?'checked':''}> Uključi prosljeđivanje</label>
<label>Protokol <select id="siProto">${['udp','tcp','tls'].map(p=>`<option value="${p}" ${s.protocol===p?'selected':''}>${p.toUpperCase()}</option>`).join('')}</select></label>
<label>Host kolektora <input id="siHost" value="${e(s.host||'')}" placeholder="siem.example.com"></label>
<label>Port <input id="siPort" type="number" min="1" max="65535" value="${s.port||514}"></label>
<label>Format <select id="siFmt">${[['rfc5424','RFC5424 syslog'],['cef','CEF'],['json','JSON']].map(([v,l])=>`<option value="${v}" ${s.format===v?'selected':''}>${l}</option>`).join('')}</select></label>
<label>Prag ozbiljnosti <select id="siSev">${['info','notice','warning','error','critical','security'].map(v=>`<option value="${v}" ${s.minSeverity===v?'selected':''}>${v}</option>`).join('')}</select></label>
<label><input id="siSkip" type="checkbox" ${s.skipVerify?'checked':''}> Prihvati samopotpisani TLS certifikat</label>
<div><button type="submit">Spremi</button> <button type="button" id="siTest" class="ghost">Test veze</button></div>
<div id="siMsg" class="muted"></div></form></div>`;
const payload=()=>({enabled:$('#siEn').checked,protocol:$('#siProto').value,host:$('#siHost').value.trim(),port:parseInt($('#siPort').value,10)||514,format:$('#siFmt').value,minSeverity:$('#siSev').value,skipVerify:$('#siSkip').checked});
$('#siemForm').onsubmit=async ev=>{ev.preventDefault();const m=$('#siMsg');m.textContent='Spremam…';try{await api('/api/siem',{method:'PUT',body:JSON.stringify(payload())});m.textContent='Spremljeno.'}catch(err){m.textContent=err.message}};
$('#siTest').onclick=async()=>{const m=$('#siMsg');m.textContent='Spremam i testiram…';try{await api('/api/siem',{method:'PUT',body:JSON.stringify(payload())});await api('/api/siem/test',{method:'POST',body:'{}'});m.textContent='Test uspješan — probni događaj poslan na kolektor.'}catch(err){m.textContent='Test nije uspio: '+err.message}}}
async function toolsPage(){let nics=[];try{nics=await api('/api/interfaces')}catch(e){}const e=escapeHtml;
$('#content').innerHTML=`<div class="panel"><h2>Mrežni alati</h2>
<p class="muted">Dijagnostika s appliancea, po želji <b>preko odabranog sučelja</b> (npr. „pingaj 1.1.1.1 preko WAN2") — provjera dosega, DNS-a i rute.</p>
${help('<b>ping</b> — dostupnost + latencija. <b>nslookup</b> — DNS razlučivanje (možeš zadati i konkretni DNS server). <b>traceroute/mtr</b> — put paketa i gubici po skoku. <b>HTTP test</b> — TCP/TLS spoj + HTTP kod (korisno za provjeru izlaza kroz određeni WAN). „Preko sučelja" veže izvor na taj NIC — tako testiraš točno WAN1 ili WAN2. Za DNS koristi polje „DNS server", za ostalo „Preko sučelja".')}
<form id="tlForm" class="stack">
<label>Alat <select id="tlTool"><option value="ping">ping</option><option value="dns">nslookup (DNS)</option><option value="trace">traceroute</option><option value="mtr">mtr</option><option value="http">HTTP test (https)</option></select></label>
<label>Cilj (host ili IP) <input id="tlHost" placeholder="1.1.1.1 ili example.com"></label>
<label>Preko sučelja (ping/trace/mtr/http) <select id="tlIface"><option value="">(bilo koji / default ruta)</option>${nics.map(n=>`<option value="${e(n.name)}">${e(nlabel(n.name))}${n.role?' · '+e(n.role):''}</option>`).join('')}</select></label>
<label>DNS server (samo za nslookup) <input id="tlServer" placeholder="npr. 192.168.50.1 (prazno = sistemski)"></label>
<div><button type="submit">Pokreni</button></div></form>
<pre id="tlOut" class="muted" style="margin-top:12px;white-space:pre-wrap;min-height:60px">Rezultat će se prikazati ovdje.</pre></div>`;
$('#tlForm').onsubmit=async ev=>{ev.preventDefault();const o=$('#tlOut');const host=$('#tlHost').value.trim();if(!host){o.textContent='Upiši cilj (host ili IP).';return}o.textContent='Izvršavam… (može potrajati par sekundi)';try{const r=await api('/api/tools',{method:'POST',body:JSON.stringify({tool:$('#tlTool').value,host,iface:$('#tlIface').value,server:$('#tlServer').value.trim()})});o.textContent=r.output||'(nema izlaza)'}catch(err){o.textContent=err.message}}}
async function webproxyPage(){const s=await api('/api/webproxy');const e=escapeHtml;
const banN=(s.bannedSites||[]).length,excN=(s.exceptionSites||[]).length,splN=(s.spliceSites||[]).length;
const cats=s.categoryCatalog||[],catOn=new Set(s.categories||[]),catN=(s.categories||[]).length;
const groups=(s.urlGroups||[]).map(g=>({name:g.name,action:g.action,domains:g.domains||[]}));
$('#content').innerHTML=`<div class="panel"><h2>Web proxy i filtriranje ${s.enabled?'<span class="badge">aktivan</span>':'<span class="badge">isključen</span>'}</h2>
<p class="muted">Squid (caching proxy) + e2guardian (filtriranje URL-ova). Klijenti postave proxy na IP appliancea (LAN) : port. Postavke su podijeljene u kartice — na kraju klikni <b>Spremi i primijeni</b>.</p>
${help('<b>Ukratko:</b> filtrira i ubrzava web promet. Na uređaju se postavi <b>proxy = IP kutije (na LAN-u) : port</b> (zadano 8080). Kutija tada <b>kešira</b> (brže učitavanje čestih stranica) i <b>filtrira</b> koje se stranice smiju otvarati. <br><br><b>Dozvoljena mreža</b> = tko smije koristiti proxy. Filtriranje ide po <b>URL grupama</b> i <b>kategorijama</b> (blokirano/dozvoljeno). <br><br><b>SSL-bump</b> (napredno) otključava filtriranje <b>sadržaja HTTPS</b> stranica — kutija dešifrira promet vlastitim certifikatom, pa ga klijenti <b>moraju imati u povjerenju</b>; osjetljive stranice (banke, zdravstvo) stavi u <b>Splice</b> listu da se NE dešifriraju (privatnost/zakon). <br><br>Savjet: za jeftino blokiranje po domeni koristi i <b>DNS filtering</b> — proxy dodaje keš i kontrolu po pojedinom URL-u. <br><i>Tehnički:</i> Squid + e2guardian.')}</div>
${tabBar('wpTabs',[['general','Općenito'],['cat','Kategorije',catN],['urls','URL grupe',banN+excN],['https','HTTPS (SSL-bump)',splN]])}
<form id="wpForm">
<div class="tabpane active" data-pane="wpTabs" data-tabkey="general"><div class="panel"><h3>Općenito</h3>
${toggle('wpEn',s.enabled,'Uključi web proxy')}
${toggle('wpFilter',s.filtering,'Filtriranje URL-ova (e2guardian)')}
<label>Port (klijentski, e2guardian) <input id="wpPort" type="number" min="1" max="65535" value="${s.filterPort||8080}"></label>
<label>Dozvoljena mreža (CIDR) <input id="wpNet" value="${e(s.allowedNetwork||'')}" placeholder="192.168.10.0/24"></label>
<p class="muted small">Klijent: postavi HTTP proxy na <code>IP-appliancea:${s.filterPort||8080}</code>. Samo uređaji iz „dozvoljene mreže" smiju koristiti proxy.</p>
</div></div>
<div class="tabpane" data-pane="wpTabs" data-tabkey="cat"><div class="panel"><h3>Kategorije <span class="badge">${catN} uključeno</span></h3>
<p class="muted small">Uključi gotovu kategoriju sadržaja da blokiraš cijelu klasu stranica jednim klikom. Domene se dodaju na blok-listu pri primjeni. Za finiju kontrolu dodaj vlastite domene u karticu <b>URL grupe</b>. Popis je početni skup — proširi ga po potrebi.</p>
${cats.length?cats.map(c=>toggle('wpCat_'+c.key,catOn.has(c.key),e(c.label)+' <span class="muted small">('+c.count+' domena)</span>')).join(''):'<p class="muted">Nema dostupnih kategorija.</p>'}
</div></div>
<div class="tabpane" data-pane="wpTabs" data-tabkey="urls">
<div class="panel"><h3>Imenovane URL grupe <span class="badge" id="wpGrpCount">${groups.length}</span></h3>
<p class="muted small">Imenovane liste domena, svaka postavljena na <b>Blokiraj</b> ili <b>Dozvoli</b>. Blok-grupe se dodaju u blokirane, dozvoli-grupe u iznimke — za organizaciju po namjeni (npr. „gosti-blokirano", „marketing-dozvoljeno").</p>
<div id="wpGrpList"></div>
<h4>Dodaj grupu</h4>
<div class="filterbar"><input id="wpGName" placeholder="naziv grupe (npr. gosti-blokirano)"><select id="wpGAction"><option value="block">Blokiraj</option><option value="allow">Dozvoli</option></select><button type="button" id="wpGAdd" class="ghost">Dodaj grupu</button></div>
<label>Domene za grupu (po retku) <textarea id="wpGDomains" rows="3" placeholder="example.com&#10;news.example.com"></textarea></label>
<div id="wpGMsg" class="muted"></div></div>
<div class="panel"><h3>Blokirane domene <span class="badge">${banN}</span></h3>
<p class="muted small">Domene koje se <b>blokiraju</b> (npr. oglasi, društvene mreže, neprikladan sadržaj). Jedna po retku, npr. <code>ads.example.com</code>, <code>facebook.com</code>.</p>
<textarea id="wpBan" rows="8" placeholder="ads.example.com&#10;facebook.com">${e((s.bannedSites||[]).join('\n'))}</textarea></div>
<div class="panel"><h3>Iznimke — uvijek dozvoli <span class="badge">${excN}</span></h3>
<p class="muted small">Domene koje se <b>nikad</b> ne blokiraju, čak i ako bi ih neko pravilo uhvatilo (npr. servisi za ažuriranje). Jedna po retku.</p>
<textarea id="wpExc" rows="5" placeholder="update.microsoft.com&#10;windowsupdate.com">${e((s.exceptionSites||[]).join('\n'))}</textarea></div></div>
<div class="tabpane" data-pane="wpTabs" data-tabkey="https"><div class="panel"><h3>HTTPS filtriranje (SSL-bump)</h3>
${toggle('wpBump',s.sslBump,'Uključi SSL-bump (dešifrira HTTPS)')}
<div class="panel error" style="margin:8px 0;padding:12px"><b>⚠ Upozorenje:</b> SSL-bump dešifrira HTTPS promet korisnika (MITM). Klijenti moraju instalirati naš CA certifikat. Obavijesti korisnike — u nekim jurisdikcijama je presretanje bez pristanka nezakonito. Osjetljive domene stavi u Splice listu.</div>
<label>SSL-bump port <input id="wpBumpPort" type="number" min="1" max="65535" value="${s.sslBumpPort||3130}"></label>
<label>Splice — NE dešifriraj (banke, zdravlje…) <span class="badge">${splN}</span> <textarea id="wpSplice" rows="4" placeholder="*.bank.hr&#10;login.gov.hr">${e((s.spliceSites||[]).join('\n'))}</textarea></label>
<div class="btnrow"><button type="button" id="wpCa" class="ghost">Preuzmi CA certifikat</button></div>
<p class="muted small">Instaliraj preuzeti CA na svaki klijent (sustav/preglednik trust store) prije korištenja SSL-bumpa.</p></div></div>
<div class="panel"><div class="btnrow"><button type="submit">Spremi i primijeni</button></div><div id="wpMsg" class="muted"></div></div>
</form>`;
wireTabs('wpTabs');
const renderGrpList=()=>{const el=$('#wpGrpList');if(!el)return;$('#wpGrpCount').textContent=groups.length;
el.innerHTML=groups.length?`<table class="compact"><thead><tr><th>Naziv</th><th>Akcija</th><th>Domene</th><th></th></tr></thead><tbody>${groups.map((g,i)=>`<tr><td><b>${e(g.name)}</b></td><td><span class="status ${g.action==='block'?'st-error':'st-healthy'}">${g.action==='block'?'Blokiraj':'Dozvoli'}</span></td><td class="muted">${g.domains.length} · ${e(g.domains.slice(0,3).join(', '))}${g.domains.length>3?'…':''}</td><td class="rowacts"><button type="button" class="wpGDel danger" data-i="${i}">Ukloni</button></td></tr>`).join('')}</tbody></table>`:'<p class="muted">Nema imenovanih grupa.</p>';
el.querySelectorAll('.wpGDel').forEach(b=>b.onclick=()=>{groups.splice(+b.dataset.i,1);renderGrpList()})};
renderGrpList();
$('#wpGAdd').onclick=()=>{const m=$('#wpGMsg');const name=$('#wpGName').value.trim();const action=$('#wpGAction').value;const domains=$('#wpGDomains').value.split(/[\n,]/).map(x=>x.trim().toLowerCase()).filter(Boolean);
if(!/^[A-Za-z0-9][A-Za-z0-9 _-]{0,39}$/.test(name)){m.textContent='Naziv grupe: 1-40 znakova (slova, brojke, razmak _ -), počni slovom/brojem.';return}
if(groups.some(g=>g.name===name)){m.textContent='Grupa s tim nazivom već postoji.';return}
if(!domains.length){m.textContent='Upiši barem jednu domenu.';return}
groups.push({name,action,domains});renderGrpList();$('#wpGName').value='';$('#wpGDomains').value='';m.textContent='Grupa dodana — klikni „Spremi i primijeni" na dnu.'};
$('#wpCa').onclick=()=>{window.open('/api/webproxy/ca','_blank')};
$('#wpForm').onsubmit=async ev=>{ev.preventDefault();const m=$('#wpMsg');const en=$('#wpEn').checked;
const lines=id=>$('#'+id).value.split(/[\n,]/).map(x=>x.trim().toLowerCase()).filter(Boolean);
const bump=$('#wpBump').checked;
const categories=(s.categoryCatalog||[]).map(c=>c.key).filter(k=>{const el=$('#wpCat_'+k);return el&&el.checked});
const body={enabled:en,filterPort:parseInt($('#wpPort').value,10)||8080,allowedNetwork:$('#wpNet').value.trim(),filtering:$('#wpFilter').checked,bannedSites:lines('wpBan'),exceptionSites:lines('wpExc'),categories,urlGroups:groups,sslBump:bump,sslBumpPort:parseInt($('#wpBumpPort').value,10)||3130,spliceSites:lines('wpSplice')};
if(en&&!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(body.allowedNetwork)){m.textContent='Dozvoljena mreža mora biti CIDR (npr. 192.168.10.0/24).';return}
if(en&&bump&&!confirm('SSL-bump dešifrira HTTPS promet korisnika. Klijenti moraju imati naš CA. Nastaviti?'))return;
m.textContent='Primjena…';try{await api('/api/webproxy',{method:'PUT',body:JSON.stringify(body)});m.textContent=en?'Primijenjeno. Proxy = IP:'+body.filterPort+(bump?' · SSL-bump port '+body.sslBumpPort+' (instaliraj CA na klijente!)':'')+'.':'Web proxy isključen.'}catch(err){m.textContent=err.message}}}
let dnsZone=null;
async function dnsPage(){const zones=await api('/api/dns/zones');const split=(await api('/api/dns/split').catch(()=>({records:[]}))).records||[];const e=escapeHtml;
$('#content').innerHTML=`${tabBar('dnsTabs',[['zone','Zone i zapisi',zones.length],['split','Split-horizon',split.length]])}
<div class="tabpane active" data-pane="dnsTabs" data-tabkey="zone">
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h2 style="margin:0">Zone (${zones.length})</h2><div class="btnrow"><button type="button" id="revNew" class="ghost" title="Kreiraj reverznu (in-addr.arpa) zonu iz subneta za PTR zapise">+ Reverzna zona</button> <button type="button" id="zoneNew">+ Dodaj zonu</button></div></div>
${help('<b>Ukratko:</b> ovdje daješ <b>imena</b> svojim uređajima i servisima u lokalnoj mreži — da tipkaš <code>server.ured.local</code> umjesto da pamtiš IP adresu. <br><br>Dodaj <b>zonu</b> (npr. <code>ured.local</code>), pa u nju zapise: <b>A</b> (ime → IP), <b>CNAME</b> (drugo ime za isti uređaj), <b>MX</b> (mail poslužitelj). Tehnički zapisi (SOA/NS) se postave sami. <br><br>Kutija je ujedno i <b>DNS</b> za klijente: lokalna imena rješava iz ovih zona, a za internet pita vanjske servere (uz sigurnosnu provjeru DNSSEC). Za blokiranje opasnih domena koristi <b>DNS filtering</b>. <br><i>Tehnički:</i> autoritativni PowerDNS + rekurzivni Unbound.')}<table><thead><tr><th>Zona</th><th>Vrsta</th><th>Serial</th><th></th></tr></thead><tbody>${zones.map(z=>`<tr><td><a href="#" class="zoneLink" data-z="${e(z.name)}">${e(z.name)}</a></td><td>${e(z.kind)}</td><td>${z.serial||''}</td><td><button class="zoneDel" data-z="${e(z.name)}">Obriši</button></td></tr>`).join('')}</tbody></table>
<form id="zoneAdd" class="stack" style="${drawerStyle}"><h4 id="zoneFormTitle" style="margin:.1rem 0 .3rem">Nova zona</h4><label>Naziv <input id="zName" placeholder="example.internal" required></label><label>Nameserveri (zarezom) <input id="zNs" placeholder="ns1.example.internal" required></label><div class="btnrow"><button type="submit">Dodaj zonu</button> <button type="button" id="zoneCancel" class="ghost">Odustani</button></div><div id="zMsg" class="muted"></div></form></div><div id="zoneDetail"></div></div>
<div class="tabpane" data-pane="dnsTabs" data-tabkey="split"><div id="splitPane"></div></div>`;
wireTabs('dnsTabs');
document.querySelectorAll('.zoneLink').forEach(el=>el.onclick=e2=>{e2.preventDefault();openZone(el.dataset.z).catch(err=>alert(err.message))});
document.querySelectorAll('.zoneDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati zonu ${el.dataset.z}? Zapisi se brišu iz PowerDNS-a.`))return;try{await api(`/api/dns/zones/${encodeURIComponent(el.dataset.z)}`,{method:'DELETE'});dnsZone=null;dnsPage()}catch(err){alert(err.message)}});
makeDrawer({form:'zoneAdd',title:'zoneFormTitle',newBtn:'zoneNew',cancel:'zoneCancel',addTitle:'Nova zona',reset:()=>{$('#zoneAdd').reset();$('#zMsg').textContent=''},focus:'zName'});
$('#zoneAdd').onsubmit=async e2=>{e2.preventDefault();$('#zMsg').textContent='';try{await api('/api/dns/zones',{method:'POST',body:JSON.stringify({name:$('#zName').value.trim(),nameservers:$('#zNs').value.split(',').map(s=>s.trim()).filter(Boolean)})});dnsPage()}catch(err){$('#zMsg').textContent=err.message}};
const revNew=$('#revNew');if(revNew)revNew.onclick=async()=>{const cidr=prompt('Subnet za reverznu (PTR) zonu — /8, /16 ili /24:','192.168.50.0/24');if(!cidr)return;const dns=(zones.find(z=>!/\.arpa\.?$/.test(z.name))||{}).name||'local';const ns=prompt('Nameserveri (zarezom):','ns.'+dns.replace(/\.$/,''));if(!ns)return;try{const r=await api('/api/dns/reverse',{method:'POST',body:JSON.stringify({cidr:cidr.trim(),nameservers:ns.split(',').map(s=>s.trim()).filter(Boolean)})});alert('Reverzna zona kreirana: '+(r.zone||''));dnsPage()}catch(err){alert(err.message)}};
renderSplitDns(split.slice());
if(dnsZone)await openZone(dnsZone)}
// renderSplitDns draws the split-horizon (split-brain) editor into #splitPane.
// Records are kept in `recs` and the whole list is PUT on every change.
function renderSplitDns(recs){const e=escapeHtml;const el=$('#splitPane');if(!el)return;
const save=async list=>{try{await api('/api/dns/split',{method:'PUT',body:JSON.stringify({records:list})});renderSplitDns(list)}catch(err){$('#spMsg')&&($('#spMsg').textContent=err.message)}};
const rows=recs.length?recs.map((r,i)=>`<tr><td><b>${e(r.name)}</b></td><td class="muted">${e(r.type)}</td><td>${e(r.internal)}</td><td>${r.external?e(r.external):'<span class="muted">rekurzija (javni DNS)</span>'}</td><td><div class="rowacts">${iconBtn('edit','Uredi','',`data-i="${i}"`).replace('iconbtn','iconbtn spEdit')}${iconBtn('del','Obriši','danger',`data-i="${i}"`).replace('iconbtn','iconbtn spDel')}</div></td></tr>`).join(''):'<tr><td colspan="5" class="muted">Nema split-horizon zapisa.</td></tr>';
el.innerHTML=`${help('<b>Ukratko:</b> isto ime — <b>dva odgovora</b>. Klijenti <b>iznutra</b> (LAN) dobiju <b>interni IP</b> i idu ravno na server; svi <b>izvana</b> dobiju <b>javni IP</b>. Tipično za <code>mail.tvrtka.hr</code> koji je javno <code>203.0.113.10</code>, a u uredu ga želiš doseći kao <code>10.10.10.10</code> bez hairpin NAT-a.<br><br>Upiši <b>ime</b> (FQDN), <b>interni IP</b> (obavezno) i po želji <b>vanjski IP</b> — ako vanjski ostaviš prazan, klijenti izvana ime rješavaju normalno preko javnog DNS-a.<br><i>Tehnički:</i> Unbound view (view-first) za LAN mreže; ostali padaju na globalni odgovor/rekurziju.')}
<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h2 style="margin:0">Split-horizon zapisi (${recs.length})</h2><button type="button" id="spNew">+ Dodaj zapis</button></div>
<table><thead><tr><th>Ime (FQDN)</th><th>Tip</th><th>Interni (LAN)</th><th>Vanjski (javni)</th><th></th></tr></thead><tbody>${rows}</tbody></table>
<form id="spAdd" class="stack" style="${drawerStyle}"><h4 id="spFormTitle" style="margin:.1rem 0 .3rem">Novi split-horizon zapis</h4>
<label>Ime (FQDN) <input id="spName" placeholder="mail.tvrtka.hr" required></label>
<label>Tip <select id="spType"><option>A</option><option>AAAA</option></select></label>
<label>Interni IP — vide klijenti iznutra <input id="spInt" placeholder="10.10.10.10" required></label>
<label>Vanjski IP — vide svi izvana (prazno = javni DNS) <input id="spExt" placeholder="203.0.113.10"></label>
<div class="btnrow"><button type="submit" id="spAddBtn">Dodaj</button> <button type="button" id="spCancel" class="ghost">Odustani</button></div><div id="spMsg" class="muted"></div></form></div>`;
let spEdit=-1;const spAddBtn=$('#spAddBtn');
const spReset=()=>{spEdit=-1;$('#spAdd').reset();if(spAddBtn)spAddBtn.textContent='Dodaj';$('#spMsg').textContent=''};
const spDrawer=makeDrawer({form:'spAdd',title:'spFormTitle',newBtn:'spNew',cancel:'spCancel',addTitle:'Novi split-horizon zapis',reset:spReset,focus:'spName'});
document.querySelectorAll('.spEdit').forEach(b=>b.onclick=()=>{const r=recs[+b.dataset.i];spEdit=+b.dataset.i;$('#spName').value=r.name||'';$('#spType').value=r.type||'A';$('#spInt').value=r.internal||'';$('#spExt').value=r.external||'';if(spAddBtn)spAddBtn.textContent='Spremi izmjene';$('#spMsg').textContent='';spDrawer.edit('Uredi split-horizon — '+(r.name||''))});
document.querySelectorAll('.spDel').forEach(b=>b.onclick=()=>{const list=recs.filter((_,j)=>j!==+b.dataset.i);save(list)});
$('#spAdd').onsubmit=ev=>{ev.preventDefault();const m=$('#spMsg');const name=$('#spName').value.trim().toLowerCase();const type=$('#spType').value;const internal=$('#spInt').value.trim();const external=$('#spExt').value.trim();
if(!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(name)){m.textContent='Ime mora biti ispravan FQDN (npr. mail.tvrtka.hr).';return}
if(!internal){m.textContent='Interni IP je obavezan.';return}
if(recs.some((r,j)=>r.name===name&&r.type===type&&j!==spEdit)){m.textContent='Zapis za to ime i tip već postoji.';return}
const list=recs.slice();if(spEdit>=0){list[spEdit]={name,type,internal,external}}else{list.push({name,type,internal,external})}
save(list)}}
async function openZone(name){dnsZone=name;const d=await api(`/api/dns/zones/${encodeURIComponent(name)}`);const hidden=['SOA','RRSIG','NSEC','NSEC3','NSEC3PARAM','DNSKEY','CDS','CDNSKEY'];const sets=(d.rrsets||[]).filter(s=>!hidden.includes(s.type));
$('#zoneDetail').innerHTML=`<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h2 style="margin:0">Zapisi — ${escapeHtml(name)}</h2><button type="button" id="recNew">+ Dodaj zapis</button></div>${sets.length>8?searchBar('recSearch','Traži zapis po imenu / vrijednosti…'):''}<table><thead><tr><th>Ime</th><th>Tip</th><th>TTL</th><th>Vrijednosti</th><th></th></tr></thead><tbody id="recTbody">${sets.map((s,i)=>`<tr><td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.type)}</td><td>${s.ttl}</td><td>${escapeHtml((s.records||[]).map(r=>r.content).join(', '))}</td><td>${s.type==='A'?`<button class="recPtr ghost" data-n="${escapeHtml(s.name)}" data-ip="${escapeHtml(((s.records||[])[0]||{}).content||'')}" title="Kreiraj PTR zapis za ovaj IP (reverzna zona subneta mora postojati)">＋PTR</button> `:''}<button class="recEdit" data-i="${i}">Uredi</button> <button class="recDel" data-n="${escapeHtml(s.name)}" data-t="${escapeHtml(s.type)}">Obriši</button></td></tr>`).join('')}</tbody></table>
<form id="recAdd" class="stack" style="${drawerStyle}"><h4 id="recFormTitle" style="margin:.1rem 0 .3rem">Novi zapis</h4><label>Ime (FQDN) <input id="rName" placeholder="host.${escapeHtml(name)}" required></label><label>Tip <select id="rType">${['A','AAAA','CNAME','TXT','MX','SRV','NS','PTR','CAA'].map(t=>`<option>${t}</option>`).join('')}</select></label><label>TTL <input id="rTtl" type="number" value="3600" min="1"></label><label>Vrijednosti (zarezom) <input id="rVal" placeholder="192.168.10.20" required></label><div class="btnrow"><button type="submit">Spremi zapis</button> <button type="button" id="recCancel" class="ghost">Odustani</button></div><div id="rMsg" class="muted"></div></form></div>`;
const recDrawer=makeDrawer({form:'recAdd',title:'recFormTitle',newBtn:'recNew',cancel:'recCancel',addTitle:'Novi zapis',reset:()=>{$('#recAdd').reset();$('#rMsg').textContent=''},focus:'rName'});
tableSearch('recSearch','recTbody');
document.querySelectorAll('.recEdit').forEach(el=>el.onclick=()=>{const s=sets[+el.dataset.i];if(!s)return;$('#rName').value=s.name||'';$('#rType').value=s.type||'A';$('#rTtl').value=s.ttl||3600;$('#rVal').value=(s.records||[]).map(r=>r.content).join(', ');$('#rMsg').textContent='Spremi zapis zamjenjuje sve vrijednosti tog zapisa.';recDrawer.edit(`Uredi zapis — ${s.name} ${s.type}`)});
document.querySelectorAll('.recDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati ${el.dataset.n} ${el.dataset.t}?`))return;try{await api(`/api/dns/zones/${encodeURIComponent(name)}/records`,{method:'PUT',body:JSON.stringify({name:el.dataset.n,type:el.dataset.t,delete:true,ttl:0,contents:[]})});openZone(name)}catch(err){alert(err.message)}});
document.querySelectorAll('.recPtr').forEach(el=>el.onclick=async()=>{const ip=el.dataset.ip,host=el.dataset.n;if(!ip){alert('Zapis nema IP.');return}if(!confirm(`Kreirati PTR: ${ip} → ${host}?\n(reverzna zona za taj subnet mora postojati — inače prvo „+ Reverzna zona“)`))return;try{const r=await api('/api/dns/ptr',{method:'POST',body:JSON.stringify({ip,hostname:host})});alert('PTR kreiran u zoni '+(r.zone||'')+'.')}catch(err){alert(err.message)}});
$('#recAdd').onsubmit=async e=>{e.preventDefault();$('#rMsg').textContent='';try{await api(`/api/dns/zones/${encodeURIComponent(name)}/records`,{method:'PUT',body:JSON.stringify({name:$('#rName').value.trim(),type:$('#rType').value,ttl:parseInt($('#rTtl').value,10)||3600,contents:$('#rVal').value.split(',').map(s=>s.trim()).filter(Boolean),delete:false})});openZone(name)}catch(err){$('#rMsg').textContent=err.message}}}
async function dhcpPage(){const get=p=>api(p).catch(e=>({err:e.message}));const [subnets,leases,resv,block,fwblock]=await Promise.all([get('/api/dhcp/subnets'),get('/api/dhcp/leases'),get('/api/dhcp/reservations'),get('/api/dhcp/blocklist'),get('/api/firewall/blocklist')]);
const blocked=(block&&block.blocked)||[];const isBlocked=m=>blocked.includes((m||'').toLowerCase());
const quar=new Set((fwblock&&fwblock.ips)||[]);const isQ=ip=>quar.has(ip);
const reserved=new Set((resv.err?[]:resv).map(x=>(x.mac||'').toLowerCase()));const isReserved=m=>reserved.has((m||'').toLowerCase());
const sub=subnets.err?`<p class="muted">${escapeHtml(subnets.err)}</p>`:`<table><thead><tr><th>ID</th><th>Subnet</th><th>Poolovi</th><th></th></tr></thead><tbody>${subnets.map(s=>`<tr><td>${s.id}</td><td>${escapeHtml(s.subnet)}</td><td>${escapeHtml((s.pools||[]).join(', '))}</td><td><button class="subEdit" data-id="${s.id}" data-subnet="${escapeHtml(s.subnet)}" data-pool="${escapeHtml((s.pools||[])[0]||'')}">Uredi</button> <button class="subDel" data-id="${s.id}">Obriši</button></td></tr>`).join('')}</tbody></table>`;
const subForm=`<form id="subForm" class="stack" style="${drawerStyle}"><h3 id="subFormTitle" style="margin:.1rem 0 .3rem">Novi subnet</h3><input type="hidden" id="subId" value="">
<label>Subnet (CIDR) <input id="subCidr" placeholder="192.168.20.0/24" required></label>
<label>Pool od <input id="subPoolStart" placeholder="192.168.20.100" required></label>
<label>Pool do <input id="subPoolEnd" placeholder="192.168.20.200" required></label>
<label>Router (gateway) <input id="subRouter" placeholder="192.168.20.1"></label>
<label>DNS serveri (zarezom) <input id="subDns" placeholder="192.168.20.1"></label>
<label>Domena <input id="subDomain" placeholder="example.internal"></label>
<label>Sučelje (opcionalno — veže DHCP na zonu/VLAN, npr. enp2.20) <input id="subIface" placeholder=""></label>
<div class="btnrow"><button type="submit">Spremi subnet</button> <button type="button" id="subCancel" class="ghost">Odustani</button></div>
<p class="muted">Promjena ide kroz transakciju: config-test → config-set → provjera → config-write (uz automatski rollback na grešku).</p>
<div id="subMsg" class="muted"></div></form>`;
const lea=leases.err?`<p class="muted">${escapeHtml(leases.err)}</p>`:`<table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Subnet</th><th>Istječe</th><th></th></tr></thead><tbody id="leaseTbody">${leases.map(l=>`<tr><td>${escapeHtml(l.ip)}</td><td>${escapeHtml(l.mac)}</td><td>${escapeHtml(l.hostname||'')}</td><td>${l.subnetId}</td><td>${l.expires?new Date(l.expires*1000).toLocaleString():''}</td><td class="rowacts">${isReserved(l.mac)?'<span class="badge">rezervirano</span>':`<button class="leaseResv ghost" data-mac="${escapeHtml(l.mac)}" data-ip="${escapeHtml(l.ip)}" data-host="${escapeHtml(l.hostname||'')}" data-sub="${l.subnetId}" title="Kreiraj DHCP rezervaciju iz ovog lease-a (fiksni IP za ovaj MAC)">Rezerviraj</button>`} ${isBlocked(l.mac)?'<span class="badge">MAC blokiran</span>':`<button class="leaseBlock danger" data-mac="${escapeHtml(l.mac)}" title="Kea odbija DHCP lease za ovaj MAC (samo novi zahtjevi)">Blokiraj</button>`} ${isQ(l.ip)?`<span class="badge">karantena</span> <button class="leaseUnq ghost" data-ip="${escapeHtml(l.ip)}">Ukloni</button>`:`<button class="leaseQuar danger" data-ip="${escapeHtml(l.ip)}" title="Trenutni firewall cutoff — blokira sav promet ovog IP-a odmah">Karantena</button>`}</td></tr>`).join('')}</tbody></table>`;
const macInfo={};(leases.err?[]:leases).forEach(l=>{if(l.mac)macInfo[l.mac.toLowerCase()]={ip:l.ip,host:l.hostname}});(resv.err?[]:resv).forEach(x=>{if(x.mac&&!macInfo[x.mac.toLowerCase()])macInfo[x.mac.toLowerCase()]={ip:x.ip,host:x.hostname}});
const blk=`<table><thead><tr><th>MAC</th><th>IP</th><th>Naziv uređaja</th><th></th></tr></thead><tbody>${blocked.length?blocked.map(m=>{const info=macInfo[m.toLowerCase()]||{};return `<tr><td>${escapeHtml(m)}</td><td class="muted">${escapeHtml(info.ip||'—')}</td><td class="muted">${escapeHtml(info.host||'—')}</td><td><button class="blkDel" data-mac="${escapeHtml(m)}">Odblokiraj</button></td></tr>`}).join(''):'<tr><td colspan="4" class="muted">Nema blokiranih klijenata.</td></tr>'}</tbody></table>`;
const res=resv.err?`<p class="muted">${escapeHtml(resv.err)}</p>`:`<table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Subnet</th><th></th></tr></thead><tbody id="resTbody">${resv.map(x=>`<tr><td>${escapeHtml(x.ip)}</td><td>${escapeHtml(x.mac)}</td><td>${escapeHtml(x.hostname||'')}</td><td>${x.subnetId}</td><td><button class="resDel" data-id="${x.id}">Obriši</button></td></tr>`).join('')}</tbody></table>`;
const subOpts=subnets.err?'<option value="1">1</option>':subnets.map(s=>`<option value="${s.id}">${s.id} — ${escapeHtml(s.subnet)}</option>`).join('');
$('#content').innerHTML=`<div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h2 style="margin:0">Subneti</h2><button type="button" id="subNew">+ Dodaj subnet</button></div>
${help('<b>Subnet</b> = mreža koju poslužuje DHCP (CIDR) + <b>pool</b> raspon adresa koje se dodjeljuju dinamički. <b>Router</b> je gateway koji se dijeli klijentima, <b>DNS serveri</b> i <b>domena</b> se također guraju. <b>Rezervacija</b> vezuje MAC na fiksni IP (stavi ga IZVAN poola). <b>Blokirani klijenti</b> (po MAC-u) ne dobivaju lease. Promjene idu kroz transakciju s validacijom i auto-rollbackom. Provjeri preklapanja u modulu <b>Konflikti</b>.')}${sub}${subForm}</div><div class="panel scroll"><h2>Aktivni leaseovi (${leases.err?'—':leases.length})</h2>${leases.err?'':searchBar('leaseSearch','Traži lease po IP / MAC / hostname…')}${lea}</div><div class="panel"><div class="btnrow" style="justify-content:space-between;align-items:center"><h2 style="margin:0">Rezervacije</h2><button type="button" id="resNew">+ Dodaj rezervaciju</button></div>${resv.err?'':searchBar('resSearch','Traži rezervaciju…')}${res}
<form id="resAdd" class="stack" style="${drawerStyle}"><h3 id="resFormTitle" style="margin:.1rem 0 .3rem">Nova rezervacija</h3><label>MAC <input id="resMac" placeholder="aa:bb:cc:dd:ee:ff" required></label><label>IP <input id="resIp" placeholder="192.168.10.50" required></label><label>Hostname <input id="resHost"></label><label>Subnet <select id="resSub">${subOpts}</select></label><div class="btnrow"><button type="submit">Dodaj rezervaciju</button> <button type="button" id="resCancel" class="ghost">Odustani</button></div><div id="resMsg" class="muted"></div></form></div>
<div class="panel"><h2>Blokirani klijenti (${blocked.length})</h2>
<p class="muted">Blokiran MAC ne dobiva DHCP lease — Kea odbacuje njegov zahtjev (DROP klasa), ali postojeći lease vrijedi do isteka. Za <b>trenutni</b> prekid mreže koristi <b>Karantenu</b> na leaseu (firewall cutoff odmah blokira sav promet tog IP-a).</p>
${blk}
<form id="blkAdd" class="stack"><label>MAC za blokiranje <input id="blkMac" placeholder="aa:bb:cc:dd:ee:ff" required></label><div><button type="submit" class="danger">Blokiraj MAC</button></div><div id="blkMsg" class="muted"></div></form></div>`;
const subPayload=()=>({subnet:$('#subCidr').value.trim(),poolStart:$('#subPoolStart').value.trim(),poolEnd:$('#subPoolEnd').value.trim(),router:$('#subRouter').value.trim(),domain:$('#subDomain').value.trim(),dnsServers:$('#subDns').value.split(',').map(s=>s.trim()).filter(Boolean),interface:$('#subIface').value.trim()});
const subReset=()=>{$('#subId').value='';['subCidr','subPoolStart','subPoolEnd','subRouter','subDns','subDomain','subIface'].forEach(i=>$('#'+i).value='');$('#subCidr').disabled=false;$('#subMsg').textContent=''};
const subDrawer=makeDrawer({form:'subForm',title:'subFormTitle',newBtn:'subNew',cancel:'subCancel',addTitle:'Novi subnet',reset:subReset,focus:'subCidr'});
makeDrawer({form:'resAdd',title:'resFormTitle',newBtn:'resNew',cancel:'resCancel',addTitle:'Nova rezervacija',reset:()=>{$('#resAdd').reset();$('#resMsg').textContent=''},focus:'resMac'});
tableSearch('leaseSearch','leaseTbody');tableSearch('resSearch','resTbody');
// Prefill the subnet form from a zone (per-zone DHCP shortcut from the Firewall page).
if(window.__zoneDhcp){const z=window.__zoneDhcp;window.__zoneDhcp=null;$('#subCidr').value=z.subnet||'';$('#subRouter').value=z.router||'';$('#subIface').value=z.iface||'';if(z.router)$('#subDns').value=z.router;$('#subMsg').textContent='Provjeri/dopuni pool raspon pa spremi.';subDrawer.edit('DHCP za zonu'+(z.name?' “'+z.name+'”':''));$('#subPoolStart').focus()}
$('#subForm').onsubmit=async e=>{e.preventDefault();$('#subMsg').textContent='Primjena…';const id=$('#subId').value;try{if(id){await api(`/api/dhcp/subnets/${id}`,{method:'PUT',body:JSON.stringify(subPayload())})}else{await api('/api/dhcp/subnets',{method:'POST',body:JSON.stringify(subPayload())})}dhcpPage()}catch(err){$('#subMsg').textContent=err.message}};
document.querySelectorAll('.subEdit').forEach(el=>el.onclick=()=>{$('#subId').value=el.dataset.id;$('#subCidr').value=el.dataset.subnet;$('#subCidr').disabled=true;const p=(el.dataset.pool||'').split('-').map(s=>s.trim());$('#subPoolStart').value=p[0]||'';$('#subPoolEnd').value=p[1]||'';$('#subMsg').textContent='CIDR se ne mijenja — za promjenu CIDR-a obriši pa dodaj subnet.';subDrawer.edit(`Uredi subnet ${el.dataset.subnet} (ID ${el.dataset.id})`)});
document.querySelectorAll('.subDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati subnet ID ${el.dataset.id}? DHCP za taj segment prestaje raditi.`))return;try{await api(`/api/dhcp/subnets/${el.dataset.id}`,{method:'DELETE'});dhcpPage()}catch(err){if(err.message.includes('force=true')&&confirm(err.message+'\n\nObrisati zajedno s rezervacijama?')){try{await api(`/api/dhcp/subnets/${el.dataset.id}?force=true`,{method:'DELETE'});dhcpPage()}catch(e2){alert(e2.message)}}else{alert(err.message)}}});
document.querySelectorAll('.resDel').forEach(el=>el.onclick=async()=>{if(!confirm('Obrisati rezervaciju?'))return;try{await api(`/api/dhcp/reservations/${el.dataset.id}`,{method:'DELETE'});dhcpPage()}catch(err){alert(err.message)}});
document.querySelectorAll('.leaseResv').forEach(el=>el.onclick=async()=>{const ip=el.dataset.ip,mac=el.dataset.mac;if(!confirm(`Rezervirati ${ip} za ${mac}? (fiksni IP za ovaj MAC pri budućim DHCP zahtjevima)`))return;el.disabled=true;try{await api('/api/dhcp/reservations',{method:'POST',body:JSON.stringify({id:0,mac,ip,hostname:el.dataset.host||'',subnetId:parseInt(el.dataset.sub,10)||0})});dhcpPage()}catch(err){el.disabled=false;alert(err.message)}});
$('#resAdd').onsubmit=async e=>{e.preventDefault();$('#resMsg').textContent='';try{await api('/api/dhcp/reservations',{method:'POST',body:JSON.stringify({mac:$('#resMac').value.trim(),ip:$('#resIp').value.trim(),hostname:$('#resHost').value.trim(),subnetId:parseInt($('#resSub').value,10),id:0})});$('#resMsg').textContent='Rezervacija dodana — aktivna je za nove DHCP zahtjeve.';dhcpPage()}catch(err){$('#resMsg').textContent=err.message}};
const blockMac=async(mac)=>{await api('/api/dhcp/blocklist',{method:'POST',body:JSON.stringify({mac})})};
document.querySelectorAll('.leaseBlock').forEach(el=>el.onclick=async()=>{if(!confirm(`Blokirati klijenta ${el.dataset.mac}?`))return;try{await blockMac(el.dataset.mac);dhcpPage()}catch(err){alert(err.message)}});
document.querySelectorAll('.leaseQuar').forEach(el=>el.onclick=async()=>{if(!confirm(`Staviti ${el.dataset.ip} u karantenu? Odmah se blokira sav promet tog hosta (firewall).`))return;try{await api('/api/firewall/block-ip',{method:'POST',body:JSON.stringify({ip:el.dataset.ip})});dhcpPage()}catch(err){alert(err.message)}});
document.querySelectorAll('.leaseUnq').forEach(el=>el.onclick=async()=>{try{await api('/api/firewall/unblock-ip',{method:'POST',body:JSON.stringify({ip:el.dataset.ip})});dhcpPage()}catch(err){alert(err.message)}});
document.querySelectorAll('.blkDel').forEach(el=>el.onclick=async()=>{try{await api(`/api/dhcp/blocklist/${encodeURIComponent(el.dataset.mac)}`,{method:'DELETE'});dhcpPage()}catch(err){alert(err.message)}});
$('#blkAdd').onsubmit=async e=>{e.preventDefault();const m=$('#blkMsg');m.textContent='';const mac=$('#blkMac').value.trim();if(!/^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(mac)){m.textContent='MAC oblika aa:bb:cc:dd:ee:ff.';return}m.textContent='Blokiram…';try{await blockMac(mac);dhcpPage()}catch(err){m.textContent=err.message}}}
async function mailPage(){const m=await api('/api/mail');const sev=['info','notice','warning','error','critical','security'];$('#content').innerHTML=`<div class="panel"><h2>SMTP postavke</h2>
${help('SMTP za slanje <b>alarma</b> (npr. pad servisa, sigurnosni događaji). Upiši server/port, kredencijale (lozinka se čuva šifrirano) i primatelje, te <b>prag ozbiljnosti</b> od kojeg se šalje. Pošalji test poruku da provjeriš postavke. Događaji se agregiraju da te ne zaspu.')}<form id="mailForm" class="stack">
<label>Server <input id="mHost" value="${escapeHtml(m.host||'')}" placeholder="smtp.smtp2go.com" required></label>
<label>Port <input id="mPort" type="number" value="${m.port||587}" min="1" max="65535" required></label>
<label>TLS <select id="mTls">${['starttls','tls','none'].map(t=>`<option ${t===m.tlsMode?'selected':''}>${t}</option>`).join('')}</select></label>
<label>From <input id="mFrom" type="email" value="${escapeHtml(m.from||'')}" placeholder="sna@example.com" required></label>
<label>Korisničko ime <input id="mUser" value="${escapeHtml(m.username||'')}"></label>
<label>Lozinka <input id="mPass" type="password" placeholder="${m.hasPassword?'•••••• (nepromijenjeno)':''}"></label>
<label>Primatelji (zarezom) <input id="mRcpt" value="${escapeHtml((m.recipients||[]).join(', '))}" required></label>
<label>Minimalna razina za alarm <select id="mSev">${sev.map(s=>`<option ${s===m.minSeverity?'selected':''}>${s}</option>`).join('')}</select></label>
<label><input id="mEnabled" type="checkbox" ${m.enabled?'checked':''}> Alarmi uključeni</label>
<div><button type="submit">Spremi</button> <button type="button" id="mailTest">Test mail</button></div>
<p class="muted">Prvi događaj šalje se odmah; duplikati se agregiraju 10 minuta pa stiže sažetak. Preporuka: prije uključivanja alarma pošaljite test.</p>
<div id="mailMsg" class="muted"></div></form></div>`;
const payload=()=>({enabled:$('#mEnabled').checked,host:$('#mHost').value.trim(),port:parseInt($('#mPort').value,10),tlsMode:$('#mTls').value,from:$('#mFrom').value.trim(),username:$('#mUser').value.trim(),password:$('#mPass').value,recipients:$('#mRcpt').value.split(',').map(s=>s.trim()).filter(Boolean),minSeverity:$('#mSev').value});
$('#mailForm').onsubmit=async e=>{e.preventDefault();$('#mailMsg').textContent='';try{await api('/api/mail',{method:'PUT',body:JSON.stringify(payload())});$('#mailMsg').textContent='Spremljeno.';$('#mPass').value=''}catch(err){$('#mailMsg').textContent=err.message}};
$('#mailTest').onclick=async()=>{$('#mailMsg').textContent='Slanje testa…';try{await api('/api/mail',{method:'PUT',body:JSON.stringify(payload())});await api('/api/mail/test',{method:'POST',body:'{}'});$('#mailMsg').textContent='Test mail poslan — provjerite sandučić.'}catch(err){$('#mailMsg').textContent=err.message}}}
async function audit(){const rows=await api('/api/audit');$('#content').innerHTML=`<div class="panel scroll"><table><thead><tr><th>Vrijeme</th><th>Razina</th><th>Korisnik</th><th>Akcija</th><th>Cilj</th><th>Rezultat</th></tr></thead><tbody>${rows.map(x=>`<tr><td>${new Date(x.time).toLocaleString()}</td><td class="sev-${escapeHtml(x.severity||'info')}">${escapeHtml(x.severity||'info')}</td><td>${escapeHtml(x.actor)}</td><td>${escapeHtml(x.action)}</td><td>${escapeHtml(x.target)}</td><td>${escapeHtml(x.result)}</td></tr>`).join('')}</tbody></table></div>`}
// escapeHtml encodes for BOTH text and attribute contexts. The textContent→
// innerHTML trick only encodes & < >, so quotes are escaped explicitly —
// otherwise a value containing " could break out of an attr="${escapeHtml(x)}"
// sink (attribute-context XSS).
function escapeHtml(v){const d=document.createElement('div');d.textContent=String(v??'');return d.innerHTML.replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
$('#loginForm').onsubmit=async e=>{e.preventDefault();$('#loginError').textContent='';try{const res=await api('/api/login',{method:'POST',body:JSON.stringify({username:$('#username').value,password:$('#password').value})});$('#password').value='';res.mustChangePassword?showForcedChange():showShell()}catch(err){$('#loginError').textContent=err.message}}
function showForcedChange(){const ov=document.createElement('div');ov.className='overlay';ov.innerHTML=`<div class="modal"><h2>Obavezna promjena lozinke</h2><p class="muted">Prva prijava (ili reset lozinke): postavite vlastitu lozinku prije nastavka. Ostale funkcije su do tada blokirane.</p><form id="fcForm" class="stack"><label>Trenutna (bootstrap) lozinka <input id="fcOld" type="password" required></label><label>Nova lozinka (min. 14 znakova) <input id="fcNew" type="password" minlength="14" required></label><label>Ponovi novu lozinku <input id="fcNew2" type="password" minlength="14" required></label><div><button type="submit">Postavi lozinku</button></div><div id="fcMsg" class="error"></div></form></div>`;document.body.appendChild(ov);
$('#fcForm').onsubmit=async e=>{e.preventDefault();if($('#fcNew').value!==$('#fcNew2').value){$('#fcMsg').textContent='Lozinke se ne podudaraju.';return}try{await api('/api/profile/password',{method:'POST',body:JSON.stringify({oldPassword:$('#fcOld').value,newPassword:$('#fcNew').value})});ov.remove();showShell()}catch(err){$('#fcMsg').textContent=err.message}}}
function runWizard(title,steps,onFinish){let idx=0;const state={};const ov=document.createElement('div');ov.className='overlay';document.body.appendChild(ov);const close=()=>ov.remove();
const draw=()=>{ov.innerHTML=`<div class="modal"><h2>${escapeHtml(title)}</h2><p class="muted">Korak ${idx+1}/${steps.length}: ${escapeHtml(steps[idx].title)}</p><div id="wizBody" class="stack">${steps[idx].render(state)}</div><div class="wizNav"><button type="button" id="wizCancel" class="ghost">Odustani</button>${idx>0?'<button type="button" id="wizBack" class="ghost">Natrag</button>':''}<button type="button" id="wizNext">${idx===steps.length-1?'Primijeni':'Dalje'}</button></div><div id="wizMsg" class="muted"></div></div>`;
$('#wizCancel').onclick=close;if(idx>0)$('#wizBack').onclick=()=>{idx--;draw()};
$('#wizNext').onclick=async()=>{const err=steps[idx].collect?steps[idx].collect(state):null;if(err){$('#wizMsg').textContent=err;return}if(idx<steps.length-1){idx++;draw()}else{$('#wizMsg').textContent='Primjena…';try{await onFinish(state);close()}catch(e){$('#wizMsg').textContent=e.message}}}};draw()}
function wizDhcpNet(){runWizard('Čarobnjak: DHCP mreža (W2)',[
{title:'Mreža',render:s=>`<label>Subnet (CIDR) <input id="w1cidr" value="${escapeHtml(s.subnet||'')}" placeholder="192.168.20.0/24"></label><label>Gateway (router) <input id="w1gw" value="${escapeHtml(s.router||'')}" placeholder="192.168.20.1"></label>`,collect:s=>{s.subnet=$('#w1cidr').value.trim();s.router=$('#w1gw').value.trim();return s.subnet?null:'Unesite subnet.'}},
{title:'Pool i opcije',render:s=>`<label>Pool od <input id="w2ps" value="${escapeHtml(s.poolStart||'')}" placeholder="192.168.20.100"></label><label>Pool do <input id="w2pe" value="${escapeHtml(s.poolEnd||'')}" placeholder="192.168.20.200"></label><label>DNS serveri (zarezom) <input id="w2dns" value="${escapeHtml(s.dns||s.router||'')}"></label><label>Domena <input id="w2dom" value="${escapeHtml(s.domain||'')}"></label>`,collect:s=>{s.poolStart=$('#w2ps').value.trim();s.poolEnd=$('#w2pe').value.trim();s.dns=$('#w2dns').value.trim();s.domain=$('#w2dom').value.trim();return(s.poolStart&&s.poolEnd)?null:'Unesite pool.'}},
{title:'Pregled',render:s=>`<p>Subnet: <b>${escapeHtml(s.subnet)}</b><br>Pool: <b>${escapeHtml(s.poolStart)} – ${escapeHtml(s.poolEnd)}</b><br>Gateway: <b>${escapeHtml(s.router||'—')}</b><br>DNS: <b>${escapeHtml(s.dns||'—')}</b><br>Domena: <b>${escapeHtml(s.domain||'—')}</b></p><p class="muted">Primjena ide kroz Kea transakciju s validacijom i automatskim rollbackom. Server odbija subnet koji se preklapa s postojećim.</p>`}],
async s=>{await api('/api/dhcp/subnets',{method:'POST',body:JSON.stringify({subnet:s.subnet,poolStart:s.poolStart,poolEnd:s.poolEnd,router:s.router,domain:s.domain,dnsServers:s.dns?s.dns.split(',').map(x=>x.trim()).filter(Boolean):[]})});openModule('dhcp')})}
async function wizReservation(){let leases=[];let subnets=[];try{leases=await api('/api/dhcp/leases')}catch(e){}try{subnets=await api('/api/dhcp/subnets')}catch(e){}
runWizard('Čarobnjak: DHCP rezervacija (W3)',[
{title:'Odabir uređaja',render:s=>`<label>Uređaj iz aktivnih leaseova <select id="w1lease"><option value="">— ručni unos —</option>${leases.map((l,i)=>`<option value="${i}" ${s.leaseIdx===String(i)?'selected':''}>${escapeHtml(l.ip)} · ${escapeHtml(l.mac)} · ${escapeHtml(l.hostname||'')}</option>`).join('')}</select></label>`,collect:s=>{s.leaseIdx=$('#w1lease').value;if(s.leaseIdx!==''){const l=leases[parseInt(s.leaseIdx,10)];s.mac=l.mac;s.ip=l.ip;s.hostname=l.hostname||'';s.subnetId=l.subnetId}return null}},
{title:'Podaci rezervacije',render:s=>`<label>MAC <input id="w2mac" value="${escapeHtml(s.mac||'')}" placeholder="aa:bb:cc:dd:ee:ff"></label><label>IP <input id="w2ip" value="${escapeHtml(s.ip||'')}"></label><label>Hostname <input id="w2host" value="${escapeHtml(s.hostname||'')}"></label><label>Subnet <select id="w2sub">${subnets.map(x=>`<option value="${x.id}" ${x.id===s.subnetId?'selected':''}>${x.id} — ${escapeHtml(x.subnet)}</option>`).join('')||'<option value="1">1</option>'}</select></label>`,collect:s=>{s.mac=$('#w2mac').value.trim();s.ip=$('#w2ip').value.trim();s.hostname=$('#w2host').value.trim();s.subnetId=parseInt($('#w2sub').value,10);return(s.mac&&s.ip)?null:'Unesite MAC i IP.'}},
{title:'Pregled',render:s=>{const sub=subnets.find(x=>x.id===s.subnetId);const pool=sub&&(sub.pools||[])[0]||'';let warn='';if(pool){const[ps,pe]=pool.split('-').map(x=>x.trim());const n=ip=>ip.split('.').reduce((a,o)=>a*256+ +o,0);try{if(n(s.ip)>=n(ps)&&n(s.ip)<=n(pe))warn='<p class="error">Upozorenje: IP je unutar dinamičkog poola — preporuka je rezervirati adresu izvan poola.</p>'}catch(e){}}
return`<p>MAC: <b>${escapeHtml(s.mac)}</b><br>IP: <b>${escapeHtml(s.ip)}</b><br>Hostname: <b>${escapeHtml(s.hostname||'—')}</b><br>Subnet ID: <b>${s.subnetId}</b></p>${warn}<p class="muted">Server odbija duplikat MAC-a u subnetu i duplikat IP-a. Rezervacija vrijedi odmah za nove DHCP zahtjeve.</p>`}}],
async s=>{await api('/api/dhcp/reservations',{method:'POST',body:JSON.stringify({id:0,mac:s.mac,ip:s.ip,hostname:s.hostname,subnetId:s.subnetId})});openModule('dhcp')})}
function wizDnsZone(){runWizard('Čarobnjak: DNS zona (W4)',[
{title:'Tip zone',render:s=>`<label>Tip <select id="w1type"><option value="forward" ${s.type!=='reverse'?'selected':''}>Forward</option><option value="reverse" ${s.type==='reverse'?'selected':''}>Reverse (PTR)</option></select></label><label>Za reverse: subnet (CIDR /24) <input id="w1sub" value="${escapeHtml(s.revSubnet||'')}" placeholder="192.168.20.0/24"></label>`,collect:s=>{s.type=$('#w1type').value;s.revSubnet=$('#w1sub').value.trim();if(s.type==='reverse'){const m=s.revSubnet.match(/^(\d+)\.(\d+)\.(\d+)\.\d+\/24$/);if(!m)return'Reverse zona u ovoj verziji traži /24 subnet.';s.name=`${m[3]}.${m[2]}.${m[1]}.in-addr.arpa`}return null}},
{title:'Ime i nameserveri',render:s=>`<label>Ime zone <input id="w2name" value="${escapeHtml(s.name||'')}" placeholder="example.internal" ${s.type==='reverse'?'readonly':''}></label><label>Nameserveri (zarezom) <input id="w2ns" value="${escapeHtml(s.ns||('ns1.'+(s.type==='reverse'?'':(s.name||''))))}" placeholder="ns1.example.internal"></label>`,collect:s=>{s.name=$('#w2name').value.trim();s.ns=$('#w2ns').value.trim();return(s.name&&s.ns)?null:'Unesite ime zone i barem jedan nameserver.'}},
{title:'Pregled',render:s=>`<p>Zona: <b>${escapeHtml(s.name)}</b> (${escapeHtml(s.type)})<br>Nameserveri: <b>${escapeHtml(s.ns)}</b></p><p class="muted">PowerDNS automatski kreira SOA i NS zapise. Kolizija s postojećom zonom bit će odbijena.</p>`}],
async s=>{await api('/api/dns/zones',{method:'POST',body:JSON.stringify({name:s.name,nameservers:s.ns.split(',').map(x=>x.trim()).filter(Boolean)})});openModule('dns')})}
const doLogout=async()=>{try{await api('/api/logout',{method:'POST',body:'{}'})}finally{showLogin()}};
$('#logout').onclick=doLogout;
$('#devBtn').onclick=e=>{e.stopPropagation();$('#devMenu').classList.toggle('hidden')};
document.addEventListener('click',e=>{if(!e.target.closest('.devmenu'))$('#devMenu').classList.add('hidden')});
$('#mLogout').onclick=doLogout;
$('#mReboot').onclick=()=>devPower('reboot');
$('#mPoweroff').onclick=()=>devPower('poweroff');
api('/api/dashboard').then(showShell).catch(showLogin);
