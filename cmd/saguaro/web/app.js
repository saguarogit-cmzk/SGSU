const modules=[['dashboard','Dashboard','Pregled mrežne infrastrukture'],['interfaces','Interfaces','Mrežni NIC-evi — status i identifikacija porta'],['dns','DNS','PowerDNS zone i zapisi'],['dhcp','DHCP','Kea subneti, rezervacije i leaseovi'],['gateway','Gateway','WAN/LAN, NAT i port forwarding'],['routing','Routing','Statičke rute — mreža do gatewaya/interfacea'],['fwrules','Firewall pravila','Aliasi (host/mreža) i custom pravila'],['ids','IDS/IPS','Suricata detekcija i prevencija upada'],['rpz','DNS filtering','RPZ blokiranje domena (radi i na slabom hardveru)'],['webproxy','Web proxy','Squid cache + e2guardian filtriranje URL-ova'],['vpn','VPN','WireGuard pristup na daljinu'],['sitevpn','Site-to-Site','WireGuard net-to-net tuneli između lokacija'],['ipsec','IPsec IKEv2','Site-to-site s trećim uređajima (Fortinet, MikroTik, Cisco…)'],['certificates','Certificates','Step CA i javni ACME certifikati'],['proxy','Reverse Proxy','Nginx aplikacije i TLS'],['monitoring','Monitoring','Zdravlje servisa i upozorenja'],['services','Servisi','Start / stop / restart servisa za troubleshooting'],['conflicts','Konflikti','Preklapanja subneta/poolova i duplikati'],['tools','Alati','Mrežni alati: ping, nslookup, traceroute, mtr'],['backup','Backup','Sigurne kopije, cilj i restore drill'],['multiwan','Multi-WAN','Više WAN veza, težine i failover'],['system','Sustav','Način rada: Gateway/UTM ili lokalni router'],['packages','Ažuriranja','Verzije servisa i sigurnosna ažuriranja'],['mail','Mail','SMTP alarmi i agregacija događaja'],['siem','SIEM / Logovi','Prosljeđivanje događaja na vanjski SIEM (syslog/CEF)'],['users','Users','Korisnici, MFA i ovlasti'],['audit','Audit log','Evidencija administratorskih promjena']];
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
await loadNicLabels();wireNavSearch();renderNav();openModule(current)}
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
  users:svg('<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3 3-5 6-5s6 2 6 5"/><path d="M16 6a3 3 0 0 1 0 6M21 20c0-2.5-1.8-4.2-4-4.7"/>'),
  audit:svg('<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h4"/>'),
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
// tabBar + wireTabs drive in-module tabs; panes are <div class="tabpane" data-pane="ID" data-tabkey="KEY">.
function tabBar(id,tabs){return `<div class="tabs" id="${id}">${tabs.map((t,i)=>`<button type="button" class="tab${i===0?' active':''}" data-tab="${escapeHtml(t[0])}">${escapeHtml(t[1])}${t[2]!=null?`<span class="badge">${t[2]}</span>`:''}</button>`).join('')}</div>`}
function wireTabs(id){const bar=document.getElementById(id);if(!bar)return;bar.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{bar.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll(`[data-pane="${id}"]`).forEach(p=>p.classList.toggle('active',p.dataset.tabkey===b.dataset.tab))})}
// toggle renders a sliding on/off switch wrapping a real checkbox (id preserved so existing reads work).
function toggle(id,checked,label,extra){return `<label class="toggle-row"><span class="toggle"><input type="checkbox" id="${id}" ${checked?'checked':''}${extra||''}><span class="track"></span></span><span>${label}</span></label>`}
const UTM_MODULES=new Set(['gateway','fwrules','ids','webproxy','vpn','sitevpn','ipsec','multiwan']);
// Each group is [title, iconKey, [moduleIds]]. The left rail shows only these
// groups; the modules of the active group appear as tabs across the top of the
// content as tabs, so the rail stays short no matter how many modules.
const NAV_GROUPS=[
 ['Status','monitoring',['dashboard','monitoring','conflicts','tools','audit']],
 ['Mreža','interfaces',['interfaces','gateway','routing','multiwan']],
 ['DNS i DHCP','dns',['dns','dhcp','rpz']],
 ['Vatrozid','fwrules',['fwrules','ids','webproxy']],
 ['VPN','vpn',['vpn','sitevpn','ipsec']],
 ['Servisi i TLS','services',['certificates','proxy','services','backup','mail','siem']],
 ['Sustav','system',['system','packages','users']],
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
const gi=groupIndexOf(id);if(gi>=0){currentGroup=gi;lastByGroup[gi]=id}
renderNav();const m=modules.find(x=>x[0]===id);$('#title').textContent=m[1];$('#description').textContent=m[2];$('#content').innerHTML='<div class="panel muted">Učitavanje…</div>';try{id==='dashboard'?await dashboard():id==='interfaces'?await interfacesPage():id==='audit'?await audit():id==='monitoring'?await monitoring():id==='mail'?await mailPage():id==='dns'?await dnsPage():id==='dhcp'?await dhcpPage():id==='users'?await usersPage():id==='gateway'?await gatewayPage():id==='routing'?await routingPage():id==='fwrules'?await fwRulesPage():id==='webproxy'?await webproxyPage():id==='ids'?await idsPage():id==='rpz'?await rpzPage():id==='proxy'?await proxyPage():id==='certificates'?await certsPage():id==='vpn'?await vpnPage():id==='backup'?await backupPage():id==='multiwan'?await multiwanPage():id==='siem'?await siemPage():id==='sitevpn'?await s2sPage():id==='ipsec'?await ipsecPage():id==='system'?await systemPage():id==='services'?await servicesCtlPage():id==='packages'?await packagesPage():id==='conflicts'?await conflictsPage():id==='tools'?await toolsPage():($('#content').innerHTML=`<div class="panel muted">Nepoznat modul: ${escapeHtml(id)}</div>`)}catch(e){$('#content').innerHTML=`<div class="panel error">${escapeHtml(e.message)}</div>`}}
function fmtRate(bps){if(!isFinite(bps)||bps<0)bps=0;if(bps>=1e9)return (bps/1e9).toFixed(2)+' Gb/s';if(bps>=1e6)return (bps/1e6).toFixed(1)+' Mb/s';if(bps>=1e3)return (bps/1e3).toFixed(0)+' kb/s';return Math.round(bps)+' b/s'}
function fmtUptime(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+'d ':'')+h+'h '+m+'m'}
function fmtBytes(n){n=+n||0;if(n>=1e9)return (n/1e9).toFixed(2)+' GB';if(n>=1e6)return (n/1e6).toFixed(1)+' MB';if(n>=1e3)return (n/1e3).toFixed(0)+' kB';return n+' B'}
function barPct(p){const cl=p>=85?'var(--err)':p>=60?'var(--warn)':'var(--brand)';return `<div class="bar"><i style="width:${Math.min(100,Math.max(0,p))}%;background:${cl}"></i></div>`}
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
<div class="panel scroll"><h2>IDS/IPS alarmi (Suricata)</h2><div id="idsAlerts" class="muted">Učitavanje…</div></div></div>`;
wireTabs('dashViews');
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
const pfParse=t=>t.split(/[\n,]/).map(s=>s.trim()).filter(Boolean).map(s=>{const p=s.split(':');return{proto:p[0],extPort:parseInt(p[1],10),destIp:p[2],destPort:parseInt(p[3],10)}});
const pfFormat=l=>(l||[]).map(p=>`${p.proto}:${p.extPort}:${p.destIp}:${p.destPort}`).join('\n');
const snatParse=t=>t.split(/\n/).map(s=>s.trim()).filter(Boolean).map(s=>{const p=s.split('->');return{source:(p[0]||'').trim(),toAddress:(p[1]||'').trim()}}).filter(r=>r.source&&r.toAddress);
const snatFormat=l=>(l||[]).map(r=>`${r.source} -> ${r.toAddress}`).join('\n');
async function gatewayPage(){const g=await api('/api/gateway');const c=g.config||{};let wans=((await api('/api/wan').catch(()=>({wans:[]}))).wans)||[];const ew=escapeHtml;
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
<div id="wanList"></div>
<h3>Dodaj / uredi WAN vezu</h3>
<form id="wanForm" class="stack">
<label>WAN port <select id="wanIf"><option value="">— odaberi port —</option>${(g.nics||[]).map(n=>`<option value="${ew(n.name)}">${ew(nlabel(n.name))}</option>`).join('')}</select></label>
<label>Način adrese <select id="wanMode"><option value="dhcp">Dinamička (DHCP)</option><option value="static">Statička</option></select></label>
<label>Metrika (manja = primarni) <input id="wanMetric" type="number" min="1" max="4000" value="100"></label>
<div id="wanStatic" style="display:none">
<label>IP adresa (CIDR) <input id="wanAddr" placeholder="203.0.113.5/24"></label>
<label>Gateway <input id="wanGw" placeholder="203.0.113.1"></label>
<label>DNS serveri (zarezom) <input id="wanDns" placeholder="1.1.1.1, 8.8.8.8"></label>
<label>Dodatne IP adrese / aliasi (CIDR, zarezom) <input id="wanAliases" placeholder="203.0.113.6/24"></label>
</div>
<div class="btnrow"><button type="submit" class="ghost">Dodaj u listu</button> <button type="button" id="wanApplyBtn">Primijeni WAN veze</button></div>
<div id="wanMsg" class="muted"></div></form></div>`;
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
<label>Port forwardi (redak: proto:vanjski:IP:unutarnji) <textarea id="gwPf" rows="3" placeholder="tcp:8443:192.168.10.5:443">${ew(pfFormat(c.portForwards))}</textarea></label>
<label>Per-WAN SNAT (redak: izvor -&gt; WAN alias IP) <textarea id="gwSnat" rows="2" placeholder="192.168.10.5 -> 203.0.113.6">${ew(snatFormat(c.snatRules))}</textarea></label>
<div class="btnrow"><button type="submit">Spremi</button> <button type="button" id="gwPreview" class="ghost">Pregled pravila</button> <button type="button" id="gwApply">Primijeni (120 s potvrda)</button></div>
<div id="gwMsg" class="muted"></div><pre id="gwRules" class="muted" style="white-space:pre-wrap"></pre></form></div>`;
const pend=g.pending?`<div class="panel error"><h2>⚠ Promjena firewalla čeka potvrdu</h2><p>Novi ruleset je aktivan. Bez potvrde unutar 120 sekundi vraća se prethodna konfiguracija.</p><div class="btnrow"><button id="gwConfirm">Potvrdi (zadrži)</button> <button id="gwRollback" class="ghost">Vrati odmah</button></div></div>`:'';
$('#content').innerHTML=`${pend}
${tabBar('gwTabs',[['wan','WAN veze'],['nat','Gateway / NAT']])}
<div class="tabpane active" data-pane="gwTabs" data-tabkey="wan"><div class="panel"><h2>Mrežni portovi</h2>${nicsTable}</div>${wanPanel}</div>
<div class="tabpane" data-pane="gwTabs" data-tabkey="nat">${gwPanel}</div>`;
wireTabs('gwTabs');
const payload=()=>({adminNetwork:$('#gwAdmin').value.trim(),clientNetwork:$('#gwClient').value.trim(),dhcpInterface:$('#gwDhcpIf').value.trim(),gatewayEnabled:$('#gwEnabled').checked,wanInterface:$('#gwWan').value,lanInterface:$('#gwLan').value,natEnabled:$('#gwNat').checked,mgmtOnLan:$('#gwMgmtLan').checked,mgmtOnWan:$('#gwMgmtWan').checked,hairpinNat:$('#gwHairpin').checked,portForwards:pfParse($('#gwPf').value),snatRules:snatParse($('#gwSnat').value)});
const save=async()=>{await api('/api/gateway',{method:'PUT',body:JSON.stringify(payload())})};
const ipOf=name=>{const n=(g.nics||[]).find(z=>z.name===name);return (n&&(n.addresses||[])[0])||''};
const modeLabel=m=>m==='static'?'Statička':'Dinamička (DHCP)';
const renderWanList=()=>{$('#wanList').innerHTML=wans.length?`<table class="compact"><thead><tr><th>WAN</th><th>Način</th><th>IP adresa (uživo)</th><th>Gateway</th><th>Metrika</th><th></th></tr></thead><tbody>${wans.map((x,i)=>`<tr><td><b>${ew(nlabel(x.interface))}</b></td><td>${ew(modeLabel(x.mode))}</td><td class="muted">${ew(x.mode==='static'?(x.address||'—'):(ipOf(x.interface)||'—'))}</td><td class="muted">${ew(x.mode==='static'?(x.gateway||'—'):'auto')}</td><td class="muted">${x.metric||100}</td><td class="rowacts"><button class="wanEdit ghost" data-i="${i}">Uredi</button> <button class="wanRm danger" data-i="${i}">Ukloni</button></td></tr>`).join('')}</tbody></table>`:'<p class="muted">Nema konfiguriranih WAN veza.</p>';
document.querySelectorAll('.wanRm').forEach(el=>el.onclick=()=>{wans.splice(+el.dataset.i,1);renderWanList()});
document.querySelectorAll('.wanEdit').forEach(el=>el.onclick=()=>{const x=wans[+el.dataset.i];const sel=$('#wanIf');
// A stored uplink can name a port this box no longer has (a NIC moved, or the
// configuration came from other hardware). Keep it selectable instead of
// silently blanking the field, which would rewrite the row on the next save.
if(x.interface&&![...sel.options].some(o=>o.value===x.interface)){sel.add(new Option(x.interface+' (nedostupan)',x.interface))}
sel.value=x.interface;$('#wanMode').value=x.mode;$('#wanMetric').value=x.metric||100;$('#wanAddr').value=x.address||'';$('#wanGw').value=x.gateway||'';$('#wanDns').value=(x.dns||[]).join(', ');$('#wanAliases').value=(x.aliases||[]).join(', ');$('#wanStatic').style.display=x.mode==='static'?'':'none';wans.splice(+el.dataset.i,1);renderWanList()});};
renderWanList();
$('#wanMode').onchange=()=>{$('#wanStatic').style.display=$('#wanMode').value==='static'?'':'none'};
$('#wanForm').onsubmit=e=>{e.preventDefault();const m=$('#wanMsg');const mode=$('#wanMode').value;const iface=$('#wanIf').value.trim();
if(!/^[a-zA-Z0-9._-]{1,15}$/.test(iface)){m.textContent='Upiši ispravno ime sučelja.';return}
const wn={interface:iface,mode,metric:parseInt($('#wanMetric').value,10)||100,dns:$('#wanDns').value.split(',').map(x=>x.trim()).filter(Boolean),aliases:$('#wanAliases').value.split(',').map(x=>x.trim()).filter(Boolean)};
if(mode==='static'){wn.address=$('#wanAddr').value.trim();wn.gateway=$('#wanGw').value.trim();if(!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(wn.address)){m.textContent='IP adresa mora biti CIDR (npr. 203.0.113.5/24).';return}if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(wn.gateway)){m.textContent='Gateway mora biti IPv4 adresa.';return}}
if(wans.some(x=>x.interface===iface)){m.textContent='To sučelje je već u listi (ukloni pa dodaj).';return}
wans.push(wn);renderWanList();['wanIf','wanAddr','wanGw','wanDns','wanAliases'].forEach(id=>$('#'+id).value='');$('#wanMetric').value=100;$('#wanMode').value='dhcp';$('#wanStatic').style.display='none';m.textContent='Dodano u listu — klikni „Primijeni WAN veze".'};
$('#wanApplyBtn').onclick=async()=>{const m=$('#wanMsg');if(!wans.length){m.textContent='Dodaj barem jedno WAN sučelje.';return}if(!confirm('Primijeniti sva WAN sučelja? Piše netplan i radi netplan apply.'))return;m.textContent='Primjena…';try{await api('/api/wan/apply',{method:'POST',body:JSON.stringify({wans})});m.textContent='WAN sučelja primijenjena.'}catch(err){m.textContent=err.message}};
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
async function multiwanPage(){const m=await api('/api/multiwan');let nics=[];try{nics=(await api('/api/gateway')).nics||[]}catch(e){}
const rows=(m.uplinks||[]).map((u,i)=>`<tr><td>${escapeHtml(u.name)}</td><td>${escapeHtml(u.interface)}</td><td>${escapeHtml(u.gateway)}</td><td>${u.weight}</td><td>${escapeHtml(u.healthCheck||'—')}</td><td><button class="wanDel" data-i="${i}">Ukloni</button></td></tr>`).join('');
$('#content').innerHTML=`<div class="panel"><h2>Multi-WAN ${m.enabled?'<span class="badge">aktivan</span>':''}</h2><table><thead><tr><th>Naziv</th><th>Interface</th><th>Gateway</th><th>Težina</th><th>Health-check</th><th></th></tr></thead><tbody>${rows}</tbody></table>
<div class="wizRow"><button id="wanAdd">Dodaj WAN</button> ${(m.uplinks||[]).length>=2?`<button id="wanApply">${m.enabled?'Ponovno primijeni':'Uključi failover'}</button> <button id="wanOff" class="ghost">Isključi</button>`:''}</div>
<p class="muted">Zahtijeva Gateway mod (W8). Ponderirani multipath default route; failover check svakih ~20 s uklanja/vraća nexthop po ping health-checku. Uz to se postavlja <b>PBR</b>: po svakom uplinku zasebna routing tablica + <code>ip rule</code> (izvor + fwmark) i nft connmark oznaka, da odgovori izlaze istim WAN-om (bez asimetrije). Nakon promjene uplinka <b>ponovno primijeni firewall</b> (za nft mangle lanac). Preporuka: simulirajte ispad prije produkcije.</p><div id="wanMsg" class="muted"></div></div>`;
const save=async(cfg)=>api('/api/multiwan/apply',{method:'POST',body:JSON.stringify(cfg)});
$('#wanAdd').onclick=()=>{const opt=nics.map(n=>n.name).join(', ');const iface=prompt('Interface'+(opt?` (${opt})`:'')+':');if(!iface)return;const gw=prompt('Gateway IP:');if(!gw)return;const name=prompt('Naziv veze:',iface)||iface;const weight=parseInt(prompt('Težina (1-256):','1'),10)||1;const hc=prompt('Health-check IP (prazno = bez):','1.1.1.1')||'';const up=(m.uplinks||[]).concat([{name:name.trim(),interface:iface.trim(),gateway:gw.trim(),weight,healthCheck:hc.trim()}]);save({enabled:m.enabled,uplinks:up}).then(()=>multiwanPage()).catch(e=>$('#wanMsg').textContent=e.message)};
document.querySelectorAll('.wanDel').forEach(el=>el.onclick=()=>{const up=(m.uplinks||[]).filter((_,j)=>j!==parseInt(el.dataset.i,10));save({enabled:up.length>=2&&m.enabled,uplinks:up}).then(()=>multiwanPage()).catch(e=>alert(e.message))});
if($('#wanApply'))$('#wanApply').onclick=async()=>{if(!confirm('Primijeniti multi-WAN? Mijenja default rutu.'))return;$('#wanMsg').textContent='Primjena…';try{await save({enabled:true,uplinks:m.uplinks});multiwanPage()}catch(e){$('#wanMsg').textContent=e.message}};
if($('#wanOff'))$('#wanOff').onclick=async()=>{try{await save({enabled:false,uplinks:m.uplinks});multiwanPage()}catch(e){alert(e.message)}}}
async function vpnPage(){const v=await api('/api/vpn');
const peers=(v.peers||[]).map(p=>`<tr><td>${escapeHtml(p.name)}</td><td>${escapeHtml(p.address)}</td><td>${p.fullTunnel?'puni tunel':'split'}</td><td>${p.expiresAt?new Date(p.expiresAt).toLocaleDateString():'—'}</td><td><button class="vpnDel" data-n="${escapeHtml(p.name)}">Ukloni</button></td></tr>`).join('');
$('#content').innerHTML=`<div class="panel"><h2>WireGuard VPN ${v.enabled?'<span class="badge">aktivan</span>':''}</h2>
${help('Ovo je <b>road-warrior</b> pristup (pojedinačni korisnici s daljine). Postavi <b>subnet</b> tunela, <b>endpoint</b> (javni host:port na koji se klijenti spajaju) i po želji DNS. Dodaj <b>peera</b> → dobiješ gotovu konfiguraciju + <b>QR kod</b> (privatni ključ se NE sprema). <b>Split</b> tunel šalje kroz VPN samo LAN mreže, <b>puni</b> sav promet. Postavi <b>istek</b> za privremeni pristup. Za spajanje dvije lokacije koristi <b>Site-to-Site</b> ili <b>IPsec</b>.')}
<form id="vpnForm" class="stack">
<label><input id="vEnabled" type="checkbox" ${v.enabled?'checked':''}> VPN uključen</label>
<label>VPN subnet <input id="vSubnet" value="${escapeHtml(v.subnet||'10.8.0.0/24')}"></label>
<label>Port <input id="vPort" type="number" value="${v.listenPort||51820}"></label>
<label>Endpoint (javna adresa:port) <input id="vEndpoint" value="${escapeHtml(v.endpoint||'')}" placeholder="vpn.example.com:51820"></label>
<label>DNS za klijente <input id="vDns" value="${escapeHtml(v.dns||'')}" placeholder="192.168.10.1"></label>
<label>Split mreže (CIDR, zarezom) <input id="vSplit" value="${escapeHtml((v.splitNetworks||[]).join(', '))}" placeholder="192.168.10.0/24"></label>
<div><button type="submit">Spremi i primijeni</button></div><div id="vMsg" class="muted"></div></form>
<p class="muted">Napomena: otvorite UDP port ${v.listenPort||51820} u firewallu (Gateway modul) i po potrebi dodajte VPN subnet u dozvoljene mreže.</p></div>
<div class="panel"><h2>Peerovi (${(v.peers||[]).length})</h2><table><thead><tr><th>Korisnik</th><th>Adresa</th><th>Profil</th><th>Vrijedi do</th><th></th></tr></thead><tbody>${peers}</tbody></table>
<div class="wizRow"><button id="vpnWiz">Wizard: VPN korisnik (W7)</button></div></div>`;
$('#vpnForm').onsubmit=async e=>{e.preventDefault();$('#vMsg').textContent='Primjena…';try{await api('/api/vpn/apply',{method:'POST',body:JSON.stringify({enabled:$('#vEnabled').checked,subnet:$('#vSubnet').value.trim(),listenPort:parseInt($('#vPort').value,10)||51820,endpoint:$('#vEndpoint').value.trim(),dns:$('#vDns').value.trim(),splitNetworks:$('#vSplit').value.split(',').map(s=>s.trim()).filter(Boolean)})});vpnPage()}catch(err){$('#vMsg').textContent=err.message}};
$('#vpnWiz').onclick=()=>wizVPNUser().catch(e=>alert(e.message));
document.querySelectorAll('.vpnDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Ukloniti peer ${el.dataset.n}? Pristup prestaje odmah.`))return;try{await api(`/api/vpn/peers/${encodeURIComponent(el.dataset.n)}`,{method:'DELETE'});vpnPage()}catch(err){alert(err.message)}})}
async function wizVPNUser(){
runWizard('Čarobnjak: VPN korisnik (W7)',[
{title:'Korisnik',render:s=>`<label>Ime korisnika/uređaja <input id="v1name" value="${escapeHtml(s.name||'')}" placeholder="ana-laptop"></label>`,collect:s=>{s.name=$('#v1name').value.trim().toLowerCase();return s.name?null:'Unesite ime.'}},
{title:'Profil tunela',render:s=>`<label>Profil <select id="v2prof"><option value="split" ${s.prof!=='full'?'selected':''}>Split — samo lokalne mreže kroz VPN</option><option value="full" ${s.prof==='full'?'selected':''}>Puni tunel — sav promet kroz VPN</option></select></label><label>Rok valjanosti (dana, 0 = bez roka) <input id="v2exp" type="number" value="${s.exp||0}" min="0"></label>`,collect:s=>{s.prof=$('#v2prof').value;s.exp=parseInt($('#v2exp').value,10)||0;return null}},
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
${help('RPZ (Response Policy Zone) je <b>DNS sinkhole</b> — blokira maliciozne/neželjene domene na razini razlučivanja (radi i na slabom hardveru, bez DPI-a). Uključi liste ili dodaj vlastite domene; upiti za te domene vraćaju NXDOMAIN ili preusmjeravanje. Djeluje na sve klijente koji koriste ovaj resolver. Za dublju inspekciju prometa koristi <b>IDS/IPS</b>.')}<p class="muted">Blokirane domene (i njihove poddomene) vraćaju NXDOMAIN kroz Unbound. Ovo je security razina koja radi na svakom hardveru — bez Suricate. Svaki pogodak se logira kao dns-filter event.</p>
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
${help('<b>IDS</b> (detekcija) samo prijavljuje sumnjiv promet; <b>IPS</b> (inline) ga i <b>blokira</b> — promet prolazi kroz Suricatu preko nftables NFQUEUE. IPS ima fail-open (ako Suricata padne, promet i dalje teče). Ažuriraj pravila (ruleset) redovito. Zahtijeva Gateway mod. Na slabijem hardveru radije koristi samo IDS + RPZ.')}<p>Način rada: ${modeInfo}</p>${hwBadge}
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
$('#content').innerHTML=`<div class="panel"><h2>Statičke rute (${routes.length})</h2>
<p class="muted">Usmjeri promet za određenu mrežu kroz zadani gateway — npr. odredište <code>10.20.0.0/16</code> preko <code>192.168.50.254</code>. Rute su trajne (vraćaju se nakon reboota). Za default rutu koristi odredište <code>default</code>.</p>
${help('<b>Odredište</b> je mreža do koje želiš doći, u CIDR obliku (npr. <code>10.20.0.0/16</code> = cijela 10.20.x.x mreža). <b>Gateway</b> je IP susjednog rutera preko kojeg se do te mreže dolazi — mora biti u tvojoj lokalnoj mreži (on-link). <b>Sučelje</b> ostavi prazno osim ako moraš forsirati izlaz kroz točno određeni NIC. <b>Metrika</b> je prioritet (manji broj = veći prioritet) kad postoji više ruta do istog odredišta. Primjer: dvije lokacije spojene preko rutera 192.168.50.254 — dodaj <code>10.20.0.0/16 → 192.168.50.254</code>.')}
<table><thead><tr><th>Odredište</th><th>Gateway</th><th>Sučelje</th><th>Metrika</th><th></th></tr></thead><tbody>
${routes.length?routes.map((r,i)=>`<tr><td><b>${escapeHtml(r.destination)}</b></td><td>${escapeHtml(r.gateway)}</td><td class="muted">${escapeHtml(r.interface||'auto')}</td><td class="muted">${r.metric||0}</td><td><button class="rtDel danger" data-i="${i}">Obriši</button></td></tr>`).join(''):'<tr><td colspan="5" class="muted">Nema statičkih ruta.</td></tr>'}
</tbody></table></div>
<div class="panel"><h3>Dodaj rutu</h3><form id="rtAdd" class="stack">
<label>Odredište (CIDR ili "default") <input id="rtDest" placeholder="10.20.0.0/16" required></label>
<label>Gateway (IPv4) <input id="rtGw" placeholder="192.168.50.254" required></label>
<label>Sučelje (opcionalno) <input id="rtIf" list="rtNics" placeholder="auto"><datalist id="rtNics">${nicOpts}</datalist></label>
<label>Metrika <input id="rtMetric" type="number" min="0" value="0"></label>
<div><button type="submit">Dodaj rutu</button></div>
<div id="rtMsg" class="muted"></div></form></div>`;
document.querySelectorAll('.rtDel').forEach(el=>el.onclick=async()=>{$('#rtMsg')&&($('#rtMsg').textContent='');const list=routes.filter((_,j)=>j!==parseInt(el.dataset.i,10));try{await save(list);routingPage()}catch(e){alert(e.message)}});
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
<div class="panel"><h3>Tuneli (${sites.length})</h3>
<table><thead><tr><th>Naziv</th><th>Endpoint</th><th>Udaljene mreže</th><th>Keepalive</th><th>PSK</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
<div class="panel"><h3>Dodaj tunel (udaljenu lokaciju)</h3><form id="s2sAdd" class="stack">
<label>Naziv <input id="stName" placeholder="ured-zagreb" required></label>
<label>Njihov javni ključ <input id="stKey" placeholder="WireGuard public key" required></label>
<label>Njihov Endpoint (host:port, prazno = pasivno) <input id="stEp" placeholder="203.0.113.5:51821"></label>
<label>Udaljene mreže (CIDR, zarezom) <input id="stNets" placeholder="192.168.20.0/24" required></label>
<label>Keepalive (s, 0 = isključeno) <input id="stKa" type="number" min="0" max="65535" value="25"></label>
<label>Preshared key (opcionalno) <input id="stPsk" placeholder="wg genpsk (opcionalno)"></label>
<div><button type="submit">Dodaj tunel</button></div>
<div id="stMsg" class="muted"></div></form></div>`;
$('#s2sForm').onsubmit=async ev=>{ev.preventDefault();const m=$('#s2sMsg');m.textContent='';
const tun=$('#s2sTun').value.trim();const local=$('#s2sLocal').value.split(',').map(x=>x.trim()).filter(Boolean);
if(tun&&!isCIDR(tun)){m.textContent='Tunel adresa mora biti CIDR (npr. 10.9.0.1/30).';return}
for(const n of local){if(!isCIDR(n)){m.textContent='Neispravna lokalna mreža: '+n;return}}
m.textContent='Primjena…';try{await api('/api/s2s/apply',{method:'POST',body:JSON.stringify({enabled:$('#s2sEnabled').checked,listenPort:parseInt($('#s2sPort').value,10)||51821,tunnelAddress:tun,localNetworks:local})});s2sPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.s2sDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati tunel ${el.dataset.n}?`))return;try{await api(`/api/s2s/sites/${encodeURIComponent(el.dataset.n)}`,{method:'DELETE'});s2sPage()}catch(err){alert(err.message)}});
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
<div class="panel"><h3>Tuneli (${conns.length})</h3>
<table><thead><tr><th>Naziv</th><th>Remote</th><th>Lokalno → Udaljeno</th><th>Način</th><th>Auth</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
<div class="panel"><h3>Dodaj / uredi tunel</h3><form id="ipAdd" class="stack">
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
<div><button type="submit">Spremi tunel</button></div>
<div id="ipaMsg" class="muted"></div></form></div>`;
if($('#ipToggle'))$('#ipToggle').onclick=async()=>{const m=$('#ipMsg');m.textContent='Primjena…';try{await api('/api/ipsec/apply',{method:'POST',body:JSON.stringify({enabled:!s.enabled})});ipsecPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.ipDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati tunel ${el.dataset.n}?`))return;try{await api(`/api/ipsec/connections/${encodeURIComponent(el.dataset.n)}`,{method:'DELETE'});ipsecPage()}catch(err){alert(err.message)}});
$('#ipAuth').onchange=()=>{const cert=$('#ipAuth').value==='cert';$('#ipPskWrap').style.display=cert?'none':'';$('#ipCertWrap').style.display=cert?'':'none'};
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
const aliasRows=aliases.length?aliases.map((a,i)=>`<tr><td><b>${e(a.name)}</b></td><td class="muted">${e(a.type)}</td><td>${e((a.values||[]).join(', '))}</td><td><div class="rowacts">${iconBtn('del','Obriši alias','danger',`data-i="${i}"`).replace('iconbtn','iconbtn alDel')}</div></td></tr>`).join(''):'<tr><td colspan="4" class="muted">Nema aliasa.</td></tr>';
const aliasVals=n=>{const a=aliases.find(x=>x.name===n);return a?(a.values||[]).join(', '):''};
const firstVal=n=>{const a=aliases.find(x=>x.name===n);const v=a&&a.values&&a.values[0]?a.values[0]:'';return v.split('-')[0].split('/')[0]};
const aliasOpt=sel=>['<option value="">(bilo koji)</option>'].concat(aliases.map(a=>`<option ${a.name===sel?'selected':''}>${e(a.name)}</option>`)).join('');
const CATS=[['','(bez)'],['lan2wan','LAN → WAN'],['wan2lan','WAN → LAN'],['wan2dmz','WAN → DMZ'],['vpn','VPN'],['local','Local (firewall)'],['other','Ostalo']];
const catLabel=c=>{const f=CATS.find(x=>x[0]===c);return f?f[1]:c};
const catOpts=sel=>CATS.map(([v,l])=>`<option value="${v}" ${v===sel?'selected':''}>${l}</option>`).join('');
const actClass=a=>a==='accept'?'st-healthy':(a==='drop'||a==='reject')?'st-error':'';
const ruleRows=rules.length?rules.map((r,i)=>{const acts=`<div class="rowacts">${iconBtn('up','Pomakni gore','',`data-i="${i}"${i===0?' disabled':''}`).replace('iconbtn','iconbtn ruUp')}${iconBtn('down','Pomakni dolje','',`data-i="${i}"${i===rules.length-1?' disabled':''}`).replace('iconbtn','iconbtn ruDown')}${iconBtn('test','Testiraj ovo pravilo','',`data-i="${i}"`).replace('iconbtn','iconbtn ruTestBtn')}${iconBtn('del','Obriši pravilo','danger',`data-i="${i}"`).replace('iconbtn','iconbtn ruDel')}</div>`;
const main=`<tr class="expandable" data-cat="${e(r.category||'')}" data-i="${i}" data-action="${e(r.action||'')}" data-enabled="${r.enabled?'1':'0'}" data-name="${e((r.name||'').toLowerCase())}"><td class="muted"><span class="chev">▶</span> ${i+1}</td><td>${r.enabled?'':'<span class="muted">(off) </span>'}<b>${e(r.name)}</b>${r.log?'<span class="chip chip-log">LOG</span>':''}${(r.fromZone||r.toZone)?`<span class="chip chip-zone">${e(r.fromZone||'*')}→${e(r.toZone||'*')}</span>`:''}</td><td>${r.category?`<span class="badge">${e(catLabel(r.category))}</span>`:'<span class="muted">—</span>'}</td><td><span class="status ${actClass(r.action)}">${e(r.action)}</span></td><td class="muted">${e(r.proto)}${r.dstPort?':'+r.dstPort:''}</td><td>${e(r.srcAlias||'any')} → ${e(r.dstAlias||'any')}</td><td class="muted small" data-cnt="${e(r.name)}">—</td><td>${acts}</td></tr>`;
const dl=(t,d)=>`<dl><dt>${t}</dt><dd>${d}</dd></dl>`;
const detail=`<tr class="row-detail hidden" data-detail="${i}" data-cat="${e(r.category||'')}"><td colspan="8"><div class="detail-inner">${dl('Stanje',r.enabled?'<span class="status st-healthy">omogućeno</span>':'<span class="status st-muted">onemogućeno</span>')}${dl('Akcija',`<span class="status ${actClass(r.action)}">${e(r.action)}</span>`)}${dl('Protokol',e(r.proto)+(r.dstPort?' · port '+r.dstPort:''))}${dl('Kategorija',r.category?e(catLabel(r.category)):'—')}${dl('Izvor ('+e(r.srcAlias||'any')+')',e(r.srcAlias?aliasVals(r.srcAlias):'bilo koji')||'—')}${dl('Odredište ('+e(r.dstAlias||'any')+')',e(r.dstAlias?aliasVals(r.dstAlias):'bilo koji')||'—')}${(r.fromZone||r.toZone)?dl('Zona',e(r.fromZone||'bilo koja')+' → '+e(r.toZone||'bilo koja')):''}${dl('Logiranje',r.log?'<span class="status st-healthy">uključeno</span>':'<span class="muted">isključeno</span>')}</div></td></tr>`;
return main+detail}).join(''):'<tr><td colspan="8" class="muted">Nema pravila.</td></tr>';
$('#content').innerHTML=`${pend}
<div class="panel"><h2>Firewall aliasi i pravila</h2>
<p class="muted">Imenovani objekti (host / mreža / raspon) i custom pravila koja ih koriste po imenu. Pravila se primjenjuju u forward lancu, po redoslijedu odozgo, prije općeg LAN→WAN propuštanja — drop/reject ima prednost. Aktivni VPN tuneli (WireGuard site-to-site, IPsec) automatski se propuštaju kroz forward policy pri primjeni — nakon dodavanja tunela ponovno primijeni firewall.</p>
${help('<b>1.</b> Napravi <b>alias</b>: ime (počinje slovom, a-z 0-9 _), tip <code>host</code> (jedan/više IP-a), <code>network</code> (CIDR) ili <code>range</code> (<code>192.168.1.10-192.168.1.20</code>), i vrijednosti odvojene zarezom. <b>2.</b> Napravi <b>pravilo</b> koje povuče alias po imenu: akcija (accept/drop/reject), protokol, izvorni i odredišni alias (prazno = bilo koji) i opcionalno port. <b>3.</b> Klikni <b>Primijeni</b> — ruleset se učita s 120 s prozorom za potvrdu (ako izgubiš pristup, vraća se stara konfiguracija). Redoslijed pravila mijenjaj strelicama ↑↓. Pravila rade u <b>Gateway</b> modu.')}
${f.configured?'':'<div class="panel error">Najprije postavi <b>Gateway</b> (mgmt/klijentska mreža) da bi mogao primijeniti pravila.</div>'}
<div class="wizRow"><button id="fwApply">Primijeni firewall (120 s potvrda)</button></div><div id="fwMsg" class="muted"></div></div>
${tabBar('fwTabs',[['pravila','Pravila',rules.length],['nat','NAT pravila',natCount],['aliasi','Aliasi',aliases.length],['zone','Zone',zones.length],['test','Test pravila']])}
<div class="tabpane active" data-pane="fwTabs" data-tabkey="pravila">
<div class="panel"><h3>Pravila (${rules.length})</h3>
<div class="filterbar">
<input id="ruSearch" type="search" placeholder="Traži po nazivu…" autocomplete="off">
<select id="ruFilter"><option value="__all">Sve kategorije</option>${catOpts('')}</select>
<select id="ruFAction"><option value="__all">Sve akcije</option><option value="accept">accept</option><option value="drop">drop</option><option value="reject">reject</option></select>
<select id="ruFStatus"><option value="__all">Sva stanja</option><option value="1">Omogućena</option><option value="0">Onemogućena</option></select>
<button type="button" id="ruFReset" class="ghost">Poništi filtre</button>
</div>
<table><thead><tr><th>#</th><th>Naziv</th><th>Kategorija</th><th>Akcija</th><th>Proto</th><th>Izvor → Odredište</th><th>Promet</th><th>Akcije</th></tr></thead><tbody id="ruTbody">${ruleRows}</tbody></table>
<p class="muted">Klikni redak za detalje. Redoslijed određuje prioritet — pravila se primjenjuju odozgo; pomiči ikonama ↑↓. Kategorija je za grupiranje/filtriranje (LAN→WAN, WAN→LAN, VPN, Local…).</p>
<form id="ruAdd" class="stack">
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
<div><button type="submit">Dodaj pravilo</button></div><div id="ruMsg" class="muted"></div></form></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="nat">
<div class="panel"><h3>NAT pravila (${natCount})</h3>
<p class="muted">Prijevod adresa: <b>Masquerade/SNAT</b> (klijenti izlaze preko WAN adrese) i <b>DNAT / port-forward</b> (vanjski port → interni poslužitelj). NAT se <b>uređuje u Gateway stranici</b> — ovo je pregled svih NAT pravila na jednom mjestu.</p>
<table><thead><tr><th>#</th><th>Tip</th><th>Original</th><th>Prevedeno</th><th>Sučelje</th></tr></thead><tbody>${natBody}</tbody></table>
<div class="btnrow"><button type="button" id="fwNatEdit" class="ghost">Uredi u Gateway →</button></div></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="aliasi">
<div class="panel"><h3>Aliasi (${aliases.length})</h3>
<table><thead><tr><th>Naziv</th><th>Tip</th><th>Vrijednosti</th><th>Akcije</th></tr></thead><tbody>${aliasRows}</tbody></table>
<form id="alAdd" class="stack">
<label>Naziv <input id="alName" placeholder="serveri_lan" required></label>
<label>Tip <select id="alType"><option value="host">host (IP adrese)</option><option value="network">network (CIDR)</option><option value="range">range (IP-IP)</option></select></label>
<label>Vrijednosti (zarezom) <input id="alVals" placeholder="192.168.10.5, 192.168.10.6" required></label>
<div><button type="submit">Dodaj alias</button></div><div id="alMsg" class="muted"></div></form></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="zone">
<div class="panel"><h3>Zone (${zones.length})</h3>
<p class="muted">Segmentiraj mrežu po povjerenju. Zadana politika: zona veće razine povjerenja može otvarati promet prema nižoj (LAN→DMZ, DMZ→internet), nikad obrnuto — pa <b>DMZ ne doseže LAN</b>, a <b>Gost je izoliran</b> od svih. Sve što nije eksplicitno dopušteno (ili port-forward/pravilo) se odbacuje.</p>
${help('Svaka zona veže <b>sučelje</b> (fizički NIC ili VLAN na njemu) i <b>mrežu</b> (CIDR) uz <b>tip</b>: <code>lan</code> (povjerljivo), <code>dmz</code> (poluizolirano — serveri dostupni izvana), <code>guest</code> (izolirano) ili <code>wan</code> (nepovjerljivo, internet). Iz tipova se izvodi automatska međuzonska politika. <b>VLAN (802.1Q):</b> upiši VLAN ID (1-4094) da zona bude tagirani VLAN na istom fizičkom portu — više izoliranih zona na jednom kabelu (npr. DMZ=VLAN20, Gost=VLAN30 na enp2). Tada upiši i <b>adresu appliancea</b> na toj zoni (npr. 10.20.0.1/24) i klikni <b>Primijeni VLAN sučelja</b> (kreira <code>enpX.ID</code> preko netplana). Za iznimke dodaj <b>pravilo</b> s poljima <i>Iz zone / U zonu</i>. <b>DNS:</b> klikni <b>Primijeni DNS za zone</b> da klijenti u zoni smiju koristiti appliance kao DNS resolver (Unbound već sluša na svim sučeljima; dodaje se samo access-control za mrežu zone). Nakon promjene zona/pravila klikni <b>Primijeni firewall</b>.')}
<table><thead><tr><th>Naziv</th><th>Tip</th><th>Sučelje</th><th>Mreža / adresa</th><th>Akcije</th></tr></thead><tbody>${zoneRows}</tbody></table>
${(hasVlan||hasInternalZone)?`<div class="wizRow">${hasVlan?'<button id="znVlanApply">Primijeni VLAN sučelja (netplan)</button>':''}${hasInternalZone?'<button id="znDnsApply" class="ghost">Primijeni DNS za zone (Unbound)</button>':''}</div><div id="znVlanMsg" class="muted"></div>`:''}
<form id="znAdd" class="stack">
<label>Naziv <input id="znName" placeholder="dmz" required></label>
<label>Tip <select id="znKind">${ZKINDS.map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}</select></label>
<label>Sučelje (fizički NIC / VLAN parent) <select id="znIf">${nics.length?nics.map(n=>`<option value="${e(n.name)}">${e(nlabel(n.name))}</option>`).join(''):'<option value="">(nema NIC-eva)</option>'}</select></label>
<label>VLAN ID (0 = bez VLAN-a) <input id="znVlan" type="number" min="0" max="4094" value="0"></label>
<label>Mreža (CIDR, prazno za WAN) <input id="znNet" placeholder="10.20.0.0/24"></label>
<label>Adresa appliancea na VLAN-u (CIDR) <input id="znAddr" placeholder="10.20.0.1/24"></label>
<div><button type="submit">Dodaj zonu</button></div><div id="znMsg" class="muted"></div></form></div></div>
<div class="tabpane" data-pane="fwTabs" data-tabkey="test">
<div class="panel"><h3>Test pravila</h3>
<p class="muted">Upiši promet pa provjeri <b>koje pravilo</b> ga hvata i <b>prolazi li</b> (simulacija nad tvojim pravilima, ne dira kernel). Primijeni pravila da test odgovara živom stanju. Savjet: ikona ⚗ na retku pravila prednapuni ovaj obrazac.</p>
<form id="ruTest" class="stack">
<label>Izvor (IP) <input id="tsSrc" placeholder="192.168.30.10"></label>
<label>Odredište (IP) <input id="tsDst" placeholder="192.168.10.5"></label>
<label>Protokol <select id="tsProto"><option value="any">any</option><option value="tcp">tcp</option><option value="udp">udp</option></select></label>
<label>Odredišni port (0 = bilo koji) <input id="tsPort" type="number" min="0" max="65535" value="0"></label>
<div><button type="submit">Testiraj</button></div></form>
<div id="tsOut" style="margin-top:10px"></div></div></div>`;
wireTabs('fwTabs');
// Live per-rule traffic counters, mapped by rule name (best effort).
(async()=>{try{const cn=(await api('/api/firewall/counters')).counters||{};document.querySelectorAll('#ruTbody [data-cnt]').forEach(td=>{const c=cn[td.dataset.cnt];if(c)td.textContent=`${fmtBytes(c.bytes)} · ${(+c.packets).toLocaleString('hr-HR')} pkt`})}catch(e){}})();
if(f.pending){$('#fwConfirm').onclick=async()=>{try{await api('/api/gateway/confirm',{method:'POST',body:'{}'});fwRulesPage()}catch(err){alert(err.message)}};$('#fwRollback').onclick=async()=>{try{await api('/api/gateway/rollback',{method:'POST',body:'{}'});fwRulesPage()}catch(err){alert(err.message)}}}
$('#fwApply').onclick=async()=>{if(!confirm('Primijeniti firewall? Bez potvrde u 120 s vraća se stara konfiguracija.'))return;const m=$('#fwMsg');m.textContent='Primjena…';try{await api('/api/firewall/apply',{method:'POST',body:'{}'});fwRulesPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.alDel').forEach(el=>el.onclick=async()=>{const list=aliases.filter((_,j)=>j!==+el.dataset.i);try{await putAliases(list);fwRulesPage()}catch(err){alert(err.message)}});
$('#alAdd').onsubmit=async ev=>{ev.preventDefault();const m=$('#alMsg');m.textContent='';const name=$('#alName').value.trim(),type=$('#alType').value,vals=$('#alVals').value.split(',').map(x=>x.trim()).filter(Boolean);
if(!/^[a-z][a-z0-9_]{0,30}$/.test(name)){m.textContent='Naziv: počni slovom, dozvoljeno a-z 0-9 _ (bez crtice).';return}
if(!vals.length){m.textContent='Upiši barem jednu vrijednost.';return}
for(const v of vals){const okv=type==='host'?isIPv4(v):type==='network'?isCIDR(v):isRange(v);if(!okv){m.textContent='Neispravna vrijednost za tip '+type+': '+v;return}}
if(aliases.some(a=>a.name===name)){m.textContent='Alias s tim imenom već postoji.';return}
try{await putAliases(aliases.concat([{name,type,values:vals}]));fwRulesPage()}catch(err){m.textContent=err.message}};
document.querySelectorAll('.ruDel').forEach(el=>el.onclick=async()=>{const list=rules.filter((_,j)=>j!==+el.dataset.i);try{await putRules(list);fwRulesPage()}catch(err){alert(err.message)}});
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
if(rules.some(r=>r.name===name)){m.textContent='Pravilo s tim imenom već postoji.';return}
const rule={name,action:$('#ruAction').value,proto,srcAlias:$('#ruSrc').value,dstAlias:$('#ruDst').value,dstPort:port,fromZone:$('#ruFromZone').value,toZone:$('#ruToZone').value,category:$('#ruCat').value,log:$('#ruLog').checked,enabled:$('#ruEnabled').checked};
try{await putRules(rules.concat([rule]));fwRulesPage()}catch(err){m.textContent=err.message}};
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
${help('<b>Explicit proxy</b>: na klijentu postaviš proxy = IP appliancea (LAN) : <b>port</b> (default 8080). Squid kešira, a <b>e2guardian</b> filtrira po <b>URL grupama</b> (blokirane/iznimke). <b>Dozvoljena mreža</b> ograničava tko smije koristiti proxy. Sinergija: <b>RPZ (DNS filtering)</b> već blokira domene jeftino na DNS razini — proxy dodaje keš i per-URL kontrolu. <b>SSL-bump</b> otključava filtriranje HTTPS <b>sadržaja</b>: Squid dešifrira TLS vlastitim CA-om (klijenti ga MORAJU imati u trustu). Osjetljive domene (banke, zdravlje) stavi u <b>Splice</b> listu da se NE dešifriraju.')}</div>
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
async function dnsPage(){const zones=await api('/api/dns/zones');
$('#content').innerHTML=`<div class="panel"><h2>Zone (${zones.length})</h2>
${help('Ovdje su <b>autoritativne</b> DNS zone (PowerDNS) — lokalni nazivi za tvoju mrežu. Dodaj zonu (npr. <code>ured.local</code>), pa u nju <b>A</b> zapise (naziv → IP), <b>CNAME</b> (alias), <b>MX</b> (mail) i sl. SOA/NS se postave automatski. Klijenti razlučuju preko Unbound resolvera koji za lokalne zone pita PowerDNS, a za internet ide rekurzivno (uz DNSSEC). Za blokiranje malicioznih domena koristi <b>DNS filtering (RPZ)</b>.')}<table><thead><tr><th>Zona</th><th>Vrsta</th><th>Serial</th><th></th></tr></thead><tbody>${zones.map(z=>`<tr><td><a href="#" class="zoneLink" data-z="${escapeHtml(z.name)}">${escapeHtml(z.name)}</a></td><td>${escapeHtml(z.kind)}</td><td>${z.serial||''}</td><td><button class="zoneDel" data-z="${escapeHtml(z.name)}">Obriši</button></td></tr>`).join('')}</tbody></table>
<form id="zoneAdd" class="stack"><h3>Nova zona</h3><label>Naziv <input id="zName" placeholder="example.internal" required></label><label>Nameserveri (zarezom) <input id="zNs" placeholder="ns1.example.internal" required></label><div><button type="submit">Dodaj zonu</button></div><div id="zMsg" class="muted"></div></form></div><div id="zoneDetail"></div>`;
document.querySelectorAll('.zoneLink').forEach(el=>el.onclick=e=>{e.preventDefault();openZone(el.dataset.z).catch(err=>alert(err.message))});
document.querySelectorAll('.zoneDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati zonu ${el.dataset.z}? Zapisi se brišu iz PowerDNS-a.`))return;try{await api(`/api/dns/zones/${encodeURIComponent(el.dataset.z)}`,{method:'DELETE'});dnsZone=null;dnsPage()}catch(err){alert(err.message)}});
$('#zoneAdd').onsubmit=async e=>{e.preventDefault();$('#zMsg').textContent='';try{await api('/api/dns/zones',{method:'POST',body:JSON.stringify({name:$('#zName').value.trim(),nameservers:$('#zNs').value.split(',').map(s=>s.trim()).filter(Boolean)})});dnsPage()}catch(err){$('#zMsg').textContent=err.message}};
if(dnsZone)await openZone(dnsZone)}
async function openZone(name){dnsZone=name;const d=await api(`/api/dns/zones/${encodeURIComponent(name)}`);const hidden=['SOA','RRSIG','NSEC','NSEC3','NSEC3PARAM','DNSKEY','CDS','CDNSKEY'];const sets=(d.rrsets||[]).filter(s=>!hidden.includes(s.type));
$('#zoneDetail').innerHTML=`<div class="panel"><h2>Zapisi — ${escapeHtml(name)}</h2><table><thead><tr><th>Ime</th><th>Tip</th><th>TTL</th><th>Vrijednosti</th><th></th></tr></thead><tbody>${sets.map(s=>`<tr><td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.type)}</td><td>${s.ttl}</td><td>${escapeHtml((s.records||[]).map(r=>r.content).join(', '))}</td><td><button class="recDel" data-n="${escapeHtml(s.name)}" data-t="${escapeHtml(s.type)}">Obriši</button></td></tr>`).join('')}</tbody></table>
<form id="recAdd" class="stack"><h3>Dodaj / uredi zapis</h3><label>Ime (FQDN) <input id="rName" placeholder="host.${escapeHtml(name)}" required></label><label>Tip <select id="rType">${['A','AAAA','CNAME','TXT','MX','SRV','NS','PTR','CAA'].map(t=>`<option>${t}</option>`).join('')}</select></label><label>TTL <input id="rTtl" type="number" value="3600" min="1"></label><label>Vrijednosti (zarezom) <input id="rVal" placeholder="192.168.10.20" required></label><div><button type="submit">Spremi zapis</button></div><div id="rMsg" class="muted"></div></form></div>`;
document.querySelectorAll('.recDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati ${el.dataset.n} ${el.dataset.t}?`))return;try{await api(`/api/dns/zones/${encodeURIComponent(name)}/records`,{method:'PUT',body:JSON.stringify({name:el.dataset.n,type:el.dataset.t,delete:true,ttl:0,contents:[]})});openZone(name)}catch(err){alert(err.message)}});
$('#recAdd').onsubmit=async e=>{e.preventDefault();$('#rMsg').textContent='';try{await api(`/api/dns/zones/${encodeURIComponent(name)}/records`,{method:'PUT',body:JSON.stringify({name:$('#rName').value.trim(),type:$('#rType').value,ttl:parseInt($('#rTtl').value,10)||3600,contents:$('#rVal').value.split(',').map(s=>s.trim()).filter(Boolean),delete:false})});openZone(name)}catch(err){$('#rMsg').textContent=err.message}}}
async function dhcpPage(){const get=p=>api(p).catch(e=>({err:e.message}));const [subnets,leases,resv,block]=await Promise.all([get('/api/dhcp/subnets'),get('/api/dhcp/leases'),get('/api/dhcp/reservations'),get('/api/dhcp/blocklist')]);
const blocked=(block&&block.blocked)||[];const isBlocked=m=>blocked.includes((m||'').toLowerCase());
const sub=subnets.err?`<p class="muted">${escapeHtml(subnets.err)}</p>`:`<table><thead><tr><th>ID</th><th>Subnet</th><th>Poolovi</th><th></th></tr></thead><tbody>${subnets.map(s=>`<tr><td>${s.id}</td><td>${escapeHtml(s.subnet)}</td><td>${escapeHtml((s.pools||[]).join(', '))}</td><td><button class="subEdit" data-id="${s.id}" data-subnet="${escapeHtml(s.subnet)}" data-pool="${escapeHtml((s.pools||[])[0]||'')}">Uredi</button> <button class="subDel" data-id="${s.id}">Obriši</button></td></tr>`).join('')}</tbody></table>`;
const subForm=`<form id="subForm" class="stack"><h3 id="subFormTitle">Novi subnet</h3><input type="hidden" id="subId" value="">
<label>Subnet (CIDR) <input id="subCidr" placeholder="192.168.20.0/24" required></label>
<label>Pool od <input id="subPoolStart" placeholder="192.168.20.100" required></label>
<label>Pool do <input id="subPoolEnd" placeholder="192.168.20.200" required></label>
<label>Router (gateway) <input id="subRouter" placeholder="192.168.20.1"></label>
<label>DNS serveri (zarezom) <input id="subDns" placeholder="192.168.20.1"></label>
<label>Domena <input id="subDomain" placeholder="example.internal"></label>
<label>Sučelje (opcionalno — veže DHCP na zonu/VLAN, npr. enp2.20) <input id="subIface" placeholder=""></label>
<div><button type="submit">Spremi subnet</button> <button type="button" id="subReset">Poništi</button></div>
<p class="muted">Promjena ide kroz transakciju: config-test → config-set → provjera → config-write (uz automatski rollback na grešku).</p>
<div id="subMsg" class="muted"></div></form>`;
const lea=leases.err?`<p class="muted">${escapeHtml(leases.err)}</p>`:`<table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Subnet</th><th>Istječe</th><th></th></tr></thead><tbody>${leases.map(l=>`<tr><td>${escapeHtml(l.ip)}</td><td>${escapeHtml(l.mac)}</td><td>${escapeHtml(l.hostname||'')}</td><td>${l.subnetId}</td><td>${l.expires?new Date(l.expires*1000).toLocaleString():''}</td><td>${isBlocked(l.mac)?'<span class="badge">blokiran</span>':`<button class="leaseBlock danger" data-mac="${escapeHtml(l.mac)}">Blokiraj</button>`}</td></tr>`).join('')}</tbody></table>`;
const macInfo={};(leases.err?[]:leases).forEach(l=>{if(l.mac)macInfo[l.mac.toLowerCase()]={ip:l.ip,host:l.hostname}});(resv.err?[]:resv).forEach(x=>{if(x.mac&&!macInfo[x.mac.toLowerCase()])macInfo[x.mac.toLowerCase()]={ip:x.ip,host:x.hostname}});
const blk=`<table><thead><tr><th>MAC</th><th>IP</th><th>Naziv uređaja</th><th></th></tr></thead><tbody>${blocked.length?blocked.map(m=>{const info=macInfo[m.toLowerCase()]||{};return `<tr><td>${escapeHtml(m)}</td><td class="muted">${escapeHtml(info.ip||'—')}</td><td class="muted">${escapeHtml(info.host||'—')}</td><td><button class="blkDel" data-mac="${escapeHtml(m)}">Odblokiraj</button></td></tr>`}).join(''):'<tr><td colspan="4" class="muted">Nema blokiranih klijenata.</td></tr>'}</tbody></table>`;
const res=resv.err?`<p class="muted">${escapeHtml(resv.err)}</p>`:`<table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Subnet</th><th></th></tr></thead><tbody>${resv.map(x=>`<tr><td>${escapeHtml(x.ip)}</td><td>${escapeHtml(x.mac)}</td><td>${escapeHtml(x.hostname||'')}</td><td>${x.subnetId}</td><td><button class="resDel" data-id="${x.id}">Obriši</button></td></tr>`).join('')}</tbody></table>`;
const subOpts=subnets.err?'<option value="1">1</option>':subnets.map(s=>`<option value="${s.id}">${s.id} — ${escapeHtml(s.subnet)}</option>`).join('');
$('#content').innerHTML=`<div class="panel"><h2>Subneti</h2>
${help('<b>Subnet</b> = mreža koju poslužuje DHCP (CIDR) + <b>pool</b> raspon adresa koje se dodjeljuju dinamički. <b>Router</b> je gateway koji se dijeli klijentima, <b>DNS serveri</b> i <b>domena</b> se također guraju. <b>Rezervacija</b> vezuje MAC na fiksni IP (stavi ga IZVAN poola). <b>Blokirani klijenti</b> (po MAC-u) ne dobivaju lease. Promjene idu kroz transakciju s validacijom i auto-rollbackom. Provjeri preklapanja u modulu <b>Konflikti</b>.')}${sub}${subForm}</div><div class="panel scroll"><h2>Aktivni leaseovi (${leases.err?'—':leases.length})</h2>${lea}</div><div class="panel"><h2>Rezervacije</h2>${res}
<form id="resAdd" class="stack"><h3>Nova rezervacija</h3><label>MAC <input id="resMac" placeholder="aa:bb:cc:dd:ee:ff" required></label><label>IP <input id="resIp" placeholder="192.168.10.50" required></label><label>Hostname <input id="resHost"></label><label>Subnet <select id="resSub">${subOpts}</select></label><div><button type="submit">Dodaj rezervaciju</button></div><div id="resMsg" class="muted"></div></form></div>
<div class="panel"><h2>Blokirani klijenti (${blocked.length})</h2>
<p class="muted">Blokiran MAC ne dobiva DHCP lease — Kea odbacuje njegov zahtjev (DROP klasa). Postojeći lease vrijedi do isteka; za trenutni prekid mreže koristi i firewall pravilo.</p>
${blk}
<form id="blkAdd" class="stack"><label>MAC za blokiranje <input id="blkMac" placeholder="aa:bb:cc:dd:ee:ff" required></label><div><button type="submit" class="danger">Blokiraj MAC</button></div><div id="blkMsg" class="muted"></div></form></div>`;
const subPayload=()=>({subnet:$('#subCidr').value.trim(),poolStart:$('#subPoolStart').value.trim(),poolEnd:$('#subPoolEnd').value.trim(),router:$('#subRouter').value.trim(),domain:$('#subDomain').value.trim(),dnsServers:$('#subDns').value.split(',').map(s=>s.trim()).filter(Boolean),interface:$('#subIface').value.trim()});
// Prefill the subnet form from a zone (per-zone DHCP shortcut from the Firewall page).
if(window.__zoneDhcp){const z=window.__zoneDhcp;window.__zoneDhcp=null;$('#subCidr').value=z.subnet||'';$('#subRouter').value=z.router||'';$('#subIface').value=z.iface||'';if(z.router)$('#subDns').value=z.router;$('#subFormTitle').textContent='DHCP za zonu'+(z.name?' “'+z.name+'”':'');$('#subMsg').textContent='Provjeri/dopuni pool raspon pa spremi.';$('#subPoolStart').focus()}
$('#subForm').onsubmit=async e=>{e.preventDefault();$('#subMsg').textContent='Primjena…';const id=$('#subId').value;try{if(id){await api(`/api/dhcp/subnets/${id}`,{method:'PUT',body:JSON.stringify(subPayload())})}else{await api('/api/dhcp/subnets',{method:'POST',body:JSON.stringify(subPayload())})}dhcpPage()}catch(err){$('#subMsg').textContent=err.message}};
$('#subReset').onclick=()=>{$('#subId').value='';$('#subFormTitle').textContent='Novi subnet';['subCidr','subPoolStart','subPoolEnd','subRouter','subDns','subDomain','subIface'].forEach(i=>$('#'+i).value='');$('#subCidr').disabled=false};
document.querySelectorAll('.subEdit').forEach(el=>el.onclick=()=>{$('#subId').value=el.dataset.id;$('#subFormTitle').textContent=`Uredi subnet ${el.dataset.subnet} (ID ${el.dataset.id})`;$('#subCidr').value=el.dataset.subnet;$('#subCidr').disabled=true;const p=(el.dataset.pool||'').split('-').map(s=>s.trim());$('#subPoolStart').value=p[0]||'';$('#subPoolEnd').value=p[1]||'';$('#subMsg').textContent='CIDR se ne mijenja — za promjenu CIDR-a obrišite pa dodajte subnet.'});
document.querySelectorAll('.subDel').forEach(el=>el.onclick=async()=>{if(!confirm(`Obrisati subnet ID ${el.dataset.id}? DHCP za taj segment prestaje raditi.`))return;try{await api(`/api/dhcp/subnets/${el.dataset.id}`,{method:'DELETE'});dhcpPage()}catch(err){if(err.message.includes('force=true')&&confirm(err.message+'\n\nObrisati zajedno s rezervacijama?')){try{await api(`/api/dhcp/subnets/${el.dataset.id}?force=true`,{method:'DELETE'});dhcpPage()}catch(e2){alert(e2.message)}}else{alert(err.message)}}});
document.querySelectorAll('.resDel').forEach(el=>el.onclick=async()=>{if(!confirm('Obrisati rezervaciju?'))return;try{await api(`/api/dhcp/reservations/${el.dataset.id}`,{method:'DELETE'});dhcpPage()}catch(err){alert(err.message)}});
$('#resAdd').onsubmit=async e=>{e.preventDefault();$('#resMsg').textContent='';try{await api('/api/dhcp/reservations',{method:'POST',body:JSON.stringify({mac:$('#resMac').value.trim(),ip:$('#resIp').value.trim(),hostname:$('#resHost').value.trim(),subnetId:parseInt($('#resSub').value,10),id:0})});$('#resMsg').textContent='Rezervacija dodana — aktivna je za nove DHCP zahtjeve.';dhcpPage()}catch(err){$('#resMsg').textContent=err.message}};
const blockMac=async(mac)=>{await api('/api/dhcp/blocklist',{method:'POST',body:JSON.stringify({mac})})};
document.querySelectorAll('.leaseBlock').forEach(el=>el.onclick=async()=>{if(!confirm(`Blokirati klijenta ${el.dataset.mac}?`))return;try{await blockMac(el.dataset.mac);dhcpPage()}catch(err){alert(err.message)}});
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
