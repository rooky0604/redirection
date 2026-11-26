# Mon Setup Twitch - detecte le materiel du PC et prepare la liste a coller sur Twitch et sur le site.
# Code source, empreinte SHA-256 et historique de chaque version (depot public) :
#   https://github.com/rooky0604/mon-setup-twitch
# Securite : ce fichier est le meme sur tous les sites. Son empreinte est publiee dans le depot public
# (Mon-Setup-Twitch.ps1.sha256) et verifiee par GitHub Actions a chaque modification. Avant de faire quoi
# que ce soit, le script compare son empreinte a celle du depot et demande de valider l'operation. Il ne
# fait que lire les informations du materiel et creer une page sur le Bureau.
# Lancer : la ligne a coller dans PowerShell donnee sur le site (page /setup/verification), ou
#   powershell -ExecutionPolicy Bypass -File .\Mon-Setup-Twitch.ps1
$SetupVersion = '1.1.0'
$SetupRepoUrl = 'https://github.com/rooky0604/mon-setup-twitch'
$SetupHashUrl = 'https://raw.githubusercontent.com/rooky0604/mon-setup-twitch/main/Mon-Setup-Twitch.ps1.sha256'
# Adresse du site : donnee par la ligne PowerShell du site ($SiteUrl), sinon lue dans la marque de
# telechargement de Windows (Zone.Identifier du fichier), sinon le site principal.
if (!$SiteUrl -and $PSCommandPath) {
    try {
        $from = Get-Content -LiteralPath $PSCommandPath -Stream Zone.Identifier -ErrorAction Stop | Where-Object { $_ -match '^(HostUrl|ReferrerUrl)=https?://' } | Select-Object -First 1
        if ($from -match '=(https?://[^/\s]+)') { $SiteUrl = $Matches[1] }
    } catch {}
}
if ("$SiteUrl" -notmatch '^https?://[^/\s]+') { $SiteUrl = 'https://lien.rooky.fr' }
$SiteUrl = "$SiteUrl".TrimEnd('/')

Write-Host ''
Write-Host "=== Mon Setup Twitch v$SetupVersion ===" -ForegroundColor Magenta
# Verification GitHub : deja faite par la ligne du site ($SetupVerified), sinon sur ce fichier.
$verif = ''
if ($SetupVerified) { $verif = "$SetupVerified" }
elseif ($PSCommandPath) {
    try {
        $ref = ("$(Invoke-RestMethod -Uri $SetupHashUrl -TimeoutSec 15)".Trim() -split '\s+')[0]
        $mine = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        if ($ref -and $mine -eq $ref) { $verif = 'OK : empreinte identique a GitHub' }
        else { $verif = "DIFFERENTE du depot GitHub (ce fichier : $mine / depot : $ref)" }
    } catch { $verif = "impossible de joindre GitHub ($($_.Exception.Message))" }
} else { $verif = 'non verifiee (script lance sans fichier ni ligne du site)' }
if ($verif -like 'OK*') { Write-Host "Verification GitHub : $verif" -ForegroundColor Green }
else {
    Write-Host "Verification GitHub : $verif" -ForegroundColor Red
    Write-Host "ATTENTION : ne continue que si tu sais d'ou vient ce fichier." -ForegroundColor Red
}
Write-Host "Code source et empreinte : $SetupRepoUrl"
Write-Host "Verifier toi-meme : $SiteUrl/setup/verification"
Write-Host 'Ce script va :'
Write-Host ' - lire les informations de ton materiel sur ce PC (processeur, carte graphique, carte mere, RAM, disques,'
Write-Host '   ecrans, peripheriques USB, et VoiceMeeter s''il est installe)'
Write-Host ' - creer la page Mon-Setup-Twitch.html sur ton Bureau et l''ouvrir dans le navigateur'
Write-Host 'Il n''envoie rien sur Internet, n''installe rien et ne modifie aucun reglage du PC.'
$answer = Read-Host "Valider l'operation ? Tape O puis Entree (autre reponse = annuler)"
if ("$answer".Trim() -notmatch '^(o|oui|y|yes)$') {
    Write-Host "Operation annulee : rien n'a ete fait." -ForegroundColor Yellow
    return
}
$ErrorActionPreference = 'Continue'
$script:SetupItems = New-Object System.Collections.ArrayList
$script:SetupErrors = New-Object System.Collections.ArrayList
function Add-SetupItem($cat,$name,$source='Windows',$qty=1,$selected=$true,$query='') {
    $name = ("$name" -replace '\s+',' ').Trim()
    if (!$name) { return }
    if (!$query) { $query=$name }
    [void]$script:SetupItems.Add([pscustomobject]@{cat=$cat;name=$name;source=$source;qty=$qty;selected=$selected;query=$query})
}
function Read-Cim($class) {
    try { $result = @(Get-CimInstance -ClassName $class -ErrorAction Stop); Write-Host "$class : $($result.Count) resultat(s)"; $result }
    catch {
        $message = "CIM $class : $($_.Exception.Message)"
        Write-Warning $message; [void]$script:SetupErrors.Add($message)
        try { Get-WmiObject -Class $class -ErrorAction Stop }
        catch { $message = "WMI $class : $($_.Exception.Message)"; Write-Warning $message; [void]$script:SetupErrors.Add($message) }
    }
}
function Decode($a) { -join ($a | Where-Object {$_ -ne 0} | ForEach-Object {[char]$_}) }
Write-Host 'Detection du materiel...' -ForegroundColor Cyan
Read-Cim Win32_Processor | ForEach-Object { Add-SetupItem 'Processeur' ($_.Name -replace '\(R\)|\(TM\)|\bCPU\b|\bProcessor\b','') }
Read-Cim Win32_VideoController | Where-Object {$_.Name -notmatch 'Microsoft|Virtual|Remote|Basic|Indirect'} | ForEach-Object { Add-SetupItem 'Carte graphique' $_.Name }
Read-Cim Win32_BaseBoard | ForEach-Object { Add-SetupItem 'Carte mere' "$($_.Manufacturer) $($_.Product)" }
Read-Cim Win32_PhysicalMemory | Group-Object Manufacturer,PartNumber,Capacity,ConfiguredClockSpeed | ForEach-Object {
 $r=$_.Group[0]; $n=$_.Count; $g=[math]::Round($r.Capacity/1GB); $ref=("$($r.Manufacturer) $($r.PartNumber)").Trim(); if(!$ref){$ref='RAM'}
 Add-SetupItem 'RAM' "$ref - $($n*$g) Go (${n}x${g} Go) - $($r.ConfiguredClockSpeed) MT/s" 'Windows' 1 $true $ref
}
Read-Cim Win32_DiskDrive | Where-Object {$_.InterfaceType -ne 'USB' -and $_.PNPDeviceID -notmatch 'USBSTOR|USB\\' -and $_.Model -notmatch 'Virtual|Generic|Card Reader'} | Group-Object Model,Size | ForEach-Object { $d=$_.Group[0]; Add-SetupItem 'Stockage' "$($d.Model) - $([math]::Round($d.Size/1e9)) Go" 'Windows' $_.Count $true $d.Model }
Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue | Where-Object Active | ForEach-Object { $n=Decode $_.UserFriendlyName; if(!$n){$n="$(Decode $_.ManufacturerName) $(Decode $_.ProductCodeID)"}; $n } | Where-Object {$_} | Group-Object | ForEach-Object { Add-SetupItem 'Ecran' $_.Name 'Windows' $_.Count }
$exclude='Virtual|Virtuel|Voicemeeter|VB-Audio|VBAN|CABLE Input|CABLE Output|Realtek|Steam Streaming|Generic|Generique|Conforme HID|HID-compliant|USB Input Device|USB Audio Device|AVRCP|Hands-Free|Remote Audio|High Definition Audio|NVIDIA Broadcast|Composite Device|USB Receiver|Root Hub|Host Controller|Peripherique d.entree USB|Souris HID|Clavier HID'
function Clean($n) { $n=("$n" -replace '^(WDM|MME|KS|ASIO):\s*','' -replace '^(Microphone|Casque|Headset|Headphones|Haut-parleurs|Speakers|Ecouteurs)\s*\((.+)\)$','$2' -replace '^\d+-\s*',''); $n.Trim() }
function Category($n,$class) {
 switch -Regex ($n) {
 'Stream Deck' {return 'Stream Deck'}
 'Capture Card|Game Capture|Cam Link|HD60|4K60' {return 'Carte capture'}
 'Webcam|Camera|C920|C922|C930|Brio|Facecam' {return 'Webcam'}
 'Microphone|\bMic\b' {return 'Microphone'}
 'Headset|Headphone|Casque|Ecouteurs' {return 'Casque'}
 'Mouse|Souris' {return 'Souris'}
 'Keyboard|Clavier' {return 'Clavier'}
 'Gamepad|Manette|Xbox Controller|DualSense' {return 'Manette'}
 }
 switch($class){'Mouse'{'Souris'} 'Keyboard'{'Clavier'} 'Camera'{'Webcam'}}
}
function Prop($id,$key){ (Get-PnpDeviceProperty -InstanceId $id -KeyName $key -ErrorAction SilentlyContinue).Data }
function Useful($n){ $n -and $n -notmatch $exclude -and $n -notmatch '^(Mouse|Souris|Keyboard|Clavier|Microphone|Casque|USB Device|HID Device)$' }
try {
 Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {$_.Class -in @('Mouse','Keyboard','HIDClass','AudioEndpoint','MEDIA','Camera','Image','USB')} | ForEach-Object {
 $p=$_; $n=$p.FriendlyName; $cat=Category $n $p.Class; $src='Windows'; $desc=Prop $p.InstanceId 'DEVPKEY_Device_BusReportedDeviceDesc'
 if((Useful $desc) -and !(Useful $n)){ $n=$desc; $src='USB/HID' }
 if(!$cat){$cat=Category $n $p.Class}
 if($cat -and !(Useful $n)) { $id=$p.InstanceId; for($i=0;$i -lt 4;$i++){ $id=Prop $id 'DEVPKEY_Device_Parent'; if(!$id){break}; $desc=Prop $id 'DEVPKEY_Device_BusReportedDeviceDesc'; if((Useful $desc) -and $desc -notmatch 'Hub|Controller|Receiver'){ $n=$desc;$src='USB parent';break } } }
 if($cat -and (Useful $n)){ $clean=Clean $n; if(Useful $clean){Add-SetupItem $cat $clean $src} }
 }
} catch { Write-Warning "Detection USB incomplete: $_"; [void]$script:SetupErrors.Add("USB : $_") }
$vmStatus='VoiceMeeter : DLL introuvable'
try {
 $dllName=if([Environment]::Is64BitProcess){'VoicemeeterRemote64.dll'}else{'VoicemeeterRemote.dll'}
 $dll=@(${env:ProgramFiles(x86)},$env:ProgramFiles) | Where-Object {$_} | ForEach-Object {Join-Path $_ "VB\Voicemeeter\$dllName"} | Where-Object {Test-Path $_} | Select-Object -First 1
 if($dll){
 if(!('VMSetupV8' -as [type])){
 Add-Type -TypeDefinition @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class VMSetupV8 {
[DllImport(@"$dll", CallingConvention=CallingConvention.StdCall)] public static extern int VBVMR_Login();
[DllImport(@"$dll", CallingConvention=CallingConvention.StdCall)] public static extern int VBVMR_Logout();
[DllImport(@"$dll", CallingConvention=CallingConvention.StdCall)] public static extern int VBVMR_Input_GetDeviceNumber();
[DllImport(@"$dll", CallingConvention=CallingConvention.StdCall)] public static extern int VBVMR_Output_GetDeviceNumber();
[DllImport(@"$dll", CharSet=CharSet.Unicode, ExactSpelling=true, CallingConvention=CallingConvention.StdCall)] public static extern int VBVMR_Input_GetDeviceDescW(int i, ref int t, StringBuilder n, StringBuilder h);
[DllImport(@"$dll", CharSet=CharSet.Unicode, ExactSpelling=true, CallingConvention=CallingConvention.StdCall)] public static extern int VBVMR_Output_GetDeviceDescW(int i, ref int t, StringBuilder n, StringBuilder h);
}
"@ -ErrorAction Stop
 }
 $login=[VMSetupV8]::VBVMR_Login(); if($login -lt 0){throw "Login $login"}
 try {
 $vmStatus='VoiceMeeter : API consultee'; Start-Sleep -Milliseconds 400
 foreach($dir in @('Input','Output')){
 $count=if($dir -eq 'Input'){[VMSetupV8]::VBVMR_Input_GetDeviceNumber()}else{[VMSetupV8]::VBVMR_Output_GetDeviceNumber()}
 for($i=0;$i -lt $count;$i++){
 $n=New-Object System.Text.StringBuilder 512; $h=New-Object System.Text.StringBuilder 512; $t=0
 $rc=if($dir -eq 'Input'){[VMSetupV8]::VBVMR_Input_GetDeviceDescW($i,[ref]$t,$n,$h)}else{[VMSetupV8]::VBVMR_Output_GetDeviceDescW($i,[ref]$t,$n,$h)}
 $raw=$n.ToString(); if($rc -ne 0 -or !(Useful $raw)){continue}; $cat=Category $raw ''; $ok=$true
 if($cat -notin @('Casque','Microphone')){$cat=if($dir -eq 'Input'){'Entree audio a verifier'}else{'Sortie audio a verifier'};$ok=$false}
 Add-SetupItem $cat (Clean $raw) 'VoiceMeeter' 1 $ok
 }
 }
 } finally {[void][VMSetupV8]::VBVMR_Logout()}
 }
} catch {$vmStatus="VoiceMeeter indisponible : $($_.Exception.Message)"}
$cleanItems=@($script:SetupItems | Group-Object {($_.cat+'|'+($_.name -replace '[^\p{L}\p{N}]','')).ToLowerInvariant()} | ForEach-Object {$x=$_.Group[0];$x.source=($_.Group.source | Sort-Object -Unique)-join ' + ';$x.qty=($_.Group.qty|Measure-Object -Maximum).Maximum;$x})
Write-Host "Materiel detecte : $($cleanItems.Count)" -ForegroundColor Cyan
$cleanItems | Select-Object cat,name,source | Format-Table -AutoSize | Out-Host
if ($cleanItems.Count -eq 0) { Write-Warning 'Aucun materiel detecte. Consulte les erreurs CIM/WMI.' }
function ConvertTo-SetupHtml($s){ return [string][System.Net.WebUtility]::HtmlEncode([string]$s) }
$ErrorActionPreference = 'Stop'
$rows=foreach($x in $cleanItems){$checked=if($x.selected){'checked'}else{''}; '<tr><td><input class="use" type="checkbox" '+$checked+'></td><td><input class="cat" value="'+(ConvertTo-SetupHtml $x.cat)+'"></td><td><input class="name" value="'+(ConvertTo-SetupHtml $x.name)+'" data-query="'+(ConvertTo-SetupHtml $x.query)+'"></td><td><input class="qty" type="number" min="1" value="'+$x.qty+'"></td><td>'+(ConvertTo-SetupHtml $x.source)+'</td><td class="shopcell"></td><td><button class="remove">X</button></td></tr>'}
$html=@'
<!doctype html><html lang="fr"><meta charset="utf-8"><title>Mon Setup Twitch</title><style>
*{box-sizing:border-box}body{background:#0e0e10;color:#eee;font:15px Arial;padding:24px}main{max-width:1450px;margin:auto}header,section{padding:24px;background:#18181b;border-radius:12px;margin-bottom:20px}header{background:#5925ad}h2{color:#bf94ff}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #444;text-align:left}input,select,textarea{background:#101014;color:white;border:1px solid #555;padding:8px;border-radius:5px;width:100%}input[type=checkbox]{width:auto;accent-color:#9146ff}.qty{width:65px}button,a{display:inline-block;background:#9146ff;color:white;border:0;border-radius:5px;padding:9px;margin:4px;cursor:pointer;text-decoration:none}textarea{min-height:250px}small{color:#bbb}.scroll{overflow:auto}.shopcell{min-width:220px}#tag{max-width:300px}.pick{background:#2a2a33}.pick.on{background:#9146ff;outline:2px solid #bf94ff}.all{margin:12px 0}.nolink{color:#bbb;font-size:13px;margin-left:6px}.site{background:#1f6f43}</style><main><header><h1>MON SETUP TWITCH</h1>Amazon France / LDLC</header><section><h2>Materiel detecte</h2><p>__STATUS__</p><p>__COUNT__ composant(s) detecte(s)</p><pre style="white-space:pre-wrap">__ERRORS__</pre><p>Les liens sont des recherches. Verifie les references et decoche les lignes inutiles.</p><p class="all"><b>Boutique pour tous :</b> <button id="amazon" class="pick">Amazon</button><button id="ldlc" class="pick">LDLC</button><button id="none" class="pick">Sans lien</button><br><small>Puis affine chaque ligne avec son menu (Amazon, LDLC ou Sans lien) ou colle un lien direct Amazon / LDLC.</small></p><button id="add">Ajouter un composant</button><button id="dedup">Nettoyer les doublons</button><div class="scroll"><table><thead><tr><th>Inclure</th><th>Composant</th><th>Modele</th><th>Qte</th><th>Source</th><th>Boutique / lien</th><th>Supprimer</th></tr></thead><tbody>__ROWS__</tbody></table></div></section><section><h2>Export Twitch et site</h2><label>Identifiant Amazon Partenaires (facultatif)<br><input id="tag" placeholder="exemple-21"></label><p><button id="copy">Copier le resultat</button><button id="save">Exporter TXT</button><a class="site" id="site" href="__SITE__/admin/setup" target="_blank" rel="noopener">Copier et ouvrir mon site</a></p><p><small>Le meme texte se colle dans le panneau "A propos" de Twitch et sur ton site (Administration &gt; Mon setup).</small></p><textarea id="out" readonly></textarea><p id="msg"></p></section></main><script>
const body=document.querySelector('tbody'), $=id=>document.getElementById(id), rows=()=>[...body.rows], field=(r,c)=>r.querySelector('.'+c), norm=s=>s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]/g,'');
function search(n,s){return s==='ldlc'?'https://www.ldlc.com/recherche/'+encodeURIComponent(n)+'/':'https://www.amazon.fr/s?k='+encodeURIComponent(n)}
function valid(v){try{let u=new URL(v);return u.protocol==='https:'&&['amazon.fr','www.amazon.fr','amzn.to','ldlc.com','www.ldlc.com'].includes(u.hostname)?u.href:''}catch{return ''}}
let allShop='amazon';
function refresh(r){let s=field(r,'shop').value;field(r,'link').value=s==='none'?'':search(field(r,'name').dataset.query||field(r,'name').value,s);update(r)}
function update(r){let s=field(r,'shop').value,a=field(r,'open'),l=field(r,'link'),off=s==='none';a.style.display=l.style.display=off?'none':'';field(r,'nolink').style.display=off?'':'none';if(!off){a.href=valid(l.value)||search(field(r,'name').value,s);a.textContent=s==='ldlc'?'LDLC':'Amazon'}generate()}
function init(r){field(r,'shopcell').innerHTML='<select class="shop"><option value="amazon">Amazon France</option><option value="ldlc">LDLC</option><option value="none">Sans lien</option></select><span class="nolink">Pas de lien</span><a class="open" target="_blank" rel="noopener noreferrer">Amazon</a><input class="link" placeholder="Lien direct ou recherche">';field(r,'shop').value=allShop;field(r,'shop').onchange=()=>refresh(r);field(r,'name').onchange=()=>{field(r,'name').dataset.query='';refresh(r)};field(r,'link').onchange=()=>update(r);field(r,'remove').onclick=()=>{r.remove();generate()};refresh(r)}
function generate(){let pc=[],per=[],seen=new Set(),aff=false;for(let r of rows()){if(!field(r,'shop')||!field(r,'use').checked)continue;let c=field(r,'cat').value.trim(),n=field(r,'name').value.trim(),k=norm(c)+'|'+norm(n);if(!c||!n||seen.has(k))continue;seen.add(k);let q=Math.max(1,parseInt(field(r,'qty').value)||1),label=n+(q>1?' (x'+q+')':''),line;if(field(r,'shop').value==='none'){line='- **'+c+':** '+label}else{let u=new URL(valid(field(r,'link').value)||search(n,field(r,'shop').value)),tag=$('tag').value.trim();if(tag&&['amazon.fr','www.amazon.fr'].includes(u.hostname)){u.searchParams.set('tag',tag);aff=true}line='- **'+c+':** ['+label+']('+u.href.replace(/\(/g,'%28').replace(/\)/g,'%29')+')'}(['processeur','cartegraphique','cartemere','ram','stockage','alimentation','boitier','refroidissement'].includes(norm(c))?pc:per).push(line)}$('out').value='## Ma configuration PC\n\n'+pc.join('\n')+'\n\n## Mes peripheriques & streaming\n\n'+per.join('\n')+(aff?'\n\nEn tant que Partenaire Amazon, je realise un benefice sur les achats remplissant les conditions requises.':'')}
async function copyOut(){generate();try{await navigator.clipboard.writeText($('out').value);$('msg').textContent='Copie !';return true}catch{$('out').select();let ok=document.execCommand('copy');$('msg').textContent=ok?'Copie !':'Utilise Ctrl+C';return ok}}
function pickAll(s){allShop=s;for(let b of document.querySelectorAll('.pick'))b.classList.toggle('on',b.id===s);for(let r of rows()){field(r,'shop').value=s;refresh(r)}}
for(let r of rows())init(r);for(let s of ['amazon','ldlc','none'])$(s).onclick=()=>pickAll(s);$('amazon').classList.add('on');body.oninput=generate;$('tag').oninput=generate;$('add').onclick=()=>{let r=body.insertRow();r.innerHTML='<td><input class="use" type="checkbox" checked></td><td><input class="cat"></td><td><input class="name"></td><td><input class="qty" type="number" min="1" value="1"></td><td>Manuel</td><td class="shopcell"></td><td><button class="remove">X</button></td>';init(r)};$('dedup').onclick=()=>{let m=new Map();for(let r of rows()){let k=norm(field(r,'cat').value)+'|'+norm(field(r,'name').value);if(k==='|')continue;if(m.has(k)){let p=m.get(k);field(p,'qty').value=Math.max(+field(p,'qty').value,+field(r,'qty').value);field(p,'use').checked||=field(r,'use').checked;r.remove()}else m.set(k,r)}generate()};$('copy').onclick=copyOut;$('site').onclick=()=>{copyOut();$('msg').textContent='Copie ! Colle le texte (Ctrl+V) sur la page qui vient de s\'ouvrir.'};$('save').onclick=()=>{generate();let u=URL.createObjectURL(new Blob([$('out').value],{type:'text/plain;charset=utf-8'})),a=document.createElement('a');a.href=u;a.download='Config-Twitch.txt';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)};generate();</script></html>
'@
# Replace each template marker explicitly; stop on any rendering error.
try {
    $ErrorActionPreference = 'Stop'
    $statusText = [string](ConvertTo-SetupHtml $vmStatus)
    $rowText = [string]($rows -join "`n")
    $countText = [string]$cleanItems.Count
    $errorText = [string](ConvertTo-SetupHtml ($script:SetupErrors -join "`n"))
    if ($cleanItems.Count -eq 0) { $errorText += "`nAucun composant detecte. Consulte PowerShell." }
    $html = $html.Replace('__STATUS__', $statusText)
    $html = $html.Replace('__COUNT__', $countText)
    $html = $html.Replace('__ERRORS__', $errorText)
    $html = $html.Replace('__ROWS__', $rowText)
    $html = $html.Replace('__SITE__', [string](ConvertTo-SetupHtml $SiteUrl))
    if ($html -match '__(STATUS|COUNT|ERRORS|ROWS|SITE)__') { throw 'Marqueurs HTML non remplaces.' }
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (!$desktop -or !(Test-Path -LiteralPath $desktop)) { $desktop = $env:TEMP }
    $report = Join-Path $desktop 'Mon-Setup-Twitch.html'
    [System.IO.File]::WriteAllText($report, $html, [System.Text.Encoding]::UTF8)
    Write-Host "Rapport cree : $report" -ForegroundColor Green
    Write-Host "Pour ton site : clique 'Copier et ouvrir mon site' puis colle le texte sur $SiteUrl/admin/setup" -ForegroundColor Yellow
    Start-Process -FilePath $report
} catch {
    Write-Host "ERREUR HTML : $($_.Exception.Message)" -ForegroundColor Red
    throw
}
