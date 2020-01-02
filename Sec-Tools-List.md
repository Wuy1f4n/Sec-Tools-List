# Sec-Tools-List

主要总结渗透中利用到的一些工具，按照ATT&CK矩阵的流程进行分类，在此基础上进行了更细致的划分。一些常用的工具（Nmap、MSF、Minikatz不在记录）

 


## Initial_Access

### 1. 信息搜集

#### 1.1 人员

* 泄露信息（浏览器、泄露数据库）

[datasploit](https://github.com/DataSploit/datasploit)

[theHarvester](https://github.com/laramies/theHarvester)

[spiderfoot](https://github.com/smicallef/spiderfoot)

* 社交信息

[ScrapedIn](https://github.com/dchrastil/ScrapedIn)：搜索 Linkedin 信息

[ThreatIngestor](https://github.com/InQuest/ThreatIngestor)：Twitter、RSS等

[sherlock](https://github.com/sherlock-project/sherlock)：在280+社交账号上搜索用户

* 文件元数据

[FOCA](https://github.com/ElevenPaths/FOCA)

[metagoofil](https://github.com/laramies/metagoofil)

[MailSniper](https://github.com/dafthack/MailSniper)

#### 1.2 供应链

* Github 泄露敏感信息搜索

[gitrob](https://github.com/michenriksen/gitrob)

[Github-Monitor](https://github.com/VKSRC/Github-Monitor)

[DumpTheGit](https://github.com/Securityautomation/DumpTheGit)

[GitPrey](https://github.com/repoog/GitPrey)

[GitMine](https://github.com/super-l/GitMiner)



#### 1.3 网络资产&架构

* 开放端口&服务

[masscan_to_nmap](https://github.com/7dog7/masscan_to_nmap)

[goscan](https://github.com/marco-lancini/goscan)

* 子域名

[aquatone](https://github.com/michenriksen/aquatone)：需要事先安装ruby环境 `apt-get install ruby-dev`

[dnsmaper](https://github.com/le4f/dnsmaper)：列出子域名的IP、国家以及经纬度

[dnsrecon](https://github.com/darkoperator/dnsrecon)

[LangSrcCurise](https://github.com/LangziFun/LangSrcCurise)：子域名监控

* 站点信息

[halive](https://github.com/gnebbia/halive)：批量获取url的返回码，用于判断子域名、URL是否在使用

[httpscan](https://github.com/zer0h/httpscan)：获取指定网段80端口的Title

[EyeWitness](https://github.com/ChrisTruncer/EyeWitness)：从文件中读取url获取网站截图

[bufferfly](https://github.com/dr0op/bufferfly)：快速确定网络资产，根据url.txt 爬取状态码、CMS、titile等

[Vxscan](https://github.com/al0ne/Vxscan)：综合扫描工具，主要用来存活验证，敏感文件探测(目录扫描/js泄露接口/html注释泄露)，WAF/CDN识别，端口扫描，指纹/服务识别，操作系统识别，POC扫描，SQL注入，绕过CDN，查询旁站等功能

[URLextractor](https://github.com/eschultze/URLextractor)：被动搜集：IP和托管商、DNS服务器、ASN号、源代码、Whois、外部链接、目录Fuzz等

[Gorecon](https://github.com/devanshbatham/Gorecon)：自动查找DNS、whois、nmap、CMS、Mail、GEO等信息

[Rock-ON](https://github.com/SilverPoision/Rock-ON)：根据域名自动化完成子域名搜索、ASN、目录、js接口等信息

[Th3inspector](https://github.com/Moham3dRiahi/Th3inspector)：查找网站信息、电话号码、邮箱、whois、子域名等信息

[machinae](https://github.com/HurricaneLabs/machinae)：从公共站点/订阅源收集有关各种与安全相关的数据的情报的工具：IP地址，域名，URL，电子邮件地址，文件哈希和SSL指纹

[pown-recon](https://github.com/pownjs/pown-recon)：网站多种信息搜集，包括Github信息等


* 防护识别 ( waf&cdn )与绕过

[wafw00f](https://github.com/EnableSecurity/wafw00f)：识别waf产品

[WhatWaf](https://github.com/Ekultek/WhatWaf)：waf识别和绕过

[WAFNinja](https://github.com/unamer/WAFNinja)

[w8fuckcdn](https://github.com/boy-hack/w8fuckcdn)：扫描指定IP检测真实

[Atlas](https://github.com/m4ll0k/Atlas)：修改sqlmap篡改绕过WAF/IDS/IPS

[Awesome-WAF](https://github.com/0xInfection/Awesome-WAF)：Waf总结及绕过方式

[identYwaf](https://github.com/stamparm/identYwaf)：支持识别80多种不同的保护产品waf


#### 1.4 搜索技术(OSINT)

[OSINT_Team_Links](https://github.com/IVMachiavelli/OSINT_Team_Links)

[awesome-osint](https://github.com/jivoi/awesome-osint)


### 2. 漏洞扫描&利用

#### 2.1 WEB 漏洞

* 敏感文件扫描

[dirhunt](https://github.com/Nekmo/dirhunt)

[BBScan](https://github.com/lijiejie/BBScan)：指定IP段，批量扫描敏感文件

[Raccoon](https://github.com/evyatarmeged/Raccoon)

[PmWebDirScan](https://github.com/pmiaowu/PmWebDirScan)

[scout](https://github.com/liamg/scout)：web目录扫描

* 源码泄露

[GitHacker](https://github.com/WangYihang/GitHacker)：.git 源码泄露利用

* 文件漏洞（文件包含、文件上传）

[FDsploit](https://github.com/chrispetrou/FDsploit)：文件包含Fuzz工具

[filegps](https://github.com/0blio/filegps)：文件上传路径测试

* 目录遍历

[dotdotpwn](https://github.com/wireghoul/dotdotpwn)

* SSRF

[SSRFmap](https://github.com/swisskyrepo/SSRFmap)

* XSS

[xsssniper](https://github.com/gbrindisi/xsssniper)

[ezXSS](https://github.com/ssl/ezXSS)

* SQL Injected

[sqlmap](https://github.com/sqlmapproject/sqlmap)

[jsql-injection](https://github.com/ron190/jsql-injection):图形化自动SQL注入利用工具，支持23种数据库

* CORS

[theftfuzzer](https://github.com/lc/theftfuzzer)

* WEB Exploit Scanner

[Osmedeus](https://github.com/j3ssie/Osmedeus)

[seccubus](https://github.com/seccubus/seccubus)：自动化漏洞扫描，定时扫描

[yasuo](https://github.com/0xsauby/yasuo)

[jaeles](https://github.com/jaeles-project/jaeles)

[zaproxy](https://github.com/zaproxy/zaproxy)：支持WIndow GUI和Linux py

[xray](https://github.com/chaitin/xray)

[wfuzz](https://github.com/xmendez/wfuzz)：web fuzz工具

#### 2.2 CMS&中间件漏洞

* CMS Exploit Scan

[VulnX](https://github.com/anouarbensaad/VulnX)：检测多种类型的Cms中的漏洞，快速cms检测，信息收集和漏洞扫描目标

[joomscan](https://github.com/rezasp/joomscan)：Joomla 漏洞扫描

[wpscan](https://github.com/wpscanteam/wpscan)：WordPress Vulnerability Scanner 

* Middleware Scan

[F-MiddlewareScan](https://github.com/re4lity/F-MiddlewareScan)：中间件漏洞扫描

[WeblogicScan](https://github.com/rabbitmask/WeblogicScan)：Weblogic 漏洞扫描

* 代码审计工具

[autoSource](https://github.com/Securityautomation/autoSource)

[seecode-audit](https://github.com/seecode-audit/seecode-audit)

[codecat](https://github.com/CoolerVoid/codecat):静态规则审计C,C++,GO,Python,javascript,Swift,PHP,Ruby,ASP and Java


#### 2.3 其他方面漏洞检测&利用工具

[routersploit](https://github.com/threat9/routersploit)：专门针对路由设备进行攻击的框架

[PRET](https://github.com/RUB-NDS/PRET)：打印机利用框架

[isf](https://github.com/dark-lbp/isf)：工控系统利用框架

[HomePWN](https://github.com/ElevenPaths/HomePWN)：物联网渗透测试框架

[dronesploit](https://github.com/dhondta/dronesploit)：无人机渗透测试框架

[ehtools](https://github.com/entynetproject/ehtools)：Wifi渗透测试框架

[trivy](https://github.com/aquasecurity/trivy)

[jackit](https://github.com/insecurityofthings/jackit)：无线键鼠利用


### 3. 社会工程学攻击


## Execution

### 1. 生成载荷

#### 1.1 Backdoor

[backdoor-apk](https://github.com/dana-at-cp/backdoor-apk)

[the-backdoor-factory](https://github.com/secretsquirrel/the-backdoor-factory)：利用exe中的空白字符跳转到payload，不破坏原exe功能

#### 1.2 Script

[SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)：支持生成hta、vbs、C#、Marco、vba等

[godofwar](https://github.com/KINGSABRI/godofwar)：生成恶意的java war载荷

[CACTUSTORCH](https://github.com/mdsecactivebreach/CACTUSTORCH)：生成恶意的js、hta等文档

[morphHTA](https://github.com/vysecurity/morphHTA)：生成恶意混淆的hta

[ps1encode](https://github.com/CroweCybersecurity/ps1encode)：生成恶意的vba、cmd、vbs、php、sct、lnk、cfm等多种脚本类型

[demiguise](https://github.com/nccgroup/demiguise)：hta

[weirdhta](https://github.com/felamos/weirdhta)：hta

[green-hat-suite](https://github.com/Green-m/green-hat-suite)：Powershell

#### 1.3 Exe&Dll

[msf-av-escape](https://github.com/peacand/msf-av-escape)：Windows 下使用使用Python二进制生成器完全无法检测Metasploit反向TCP / HTTPS暂存器

#### 1.4 多种载荷生成器

[donut](https://github.com/TheWover/donut)：生成x86和x64位置无关的shellcode，从内存加载.NET程序集并使用参数运行它们

[avet](https://github.com/govolution/avet)：Virustotal：21/69

[Veil](https://github.com/Veil-Framework/Veil)：Virustotal：25/55

[TheFatRat](https://github.com/Screetsec/TheFatRat)：快速生成和MSF联动的payload，可以加壳和exe植入后门，支持快速替换图标。Virustotal：21/69

[venom](https://github.com/r00t-3xp10it/venom)

[TikiTorch](https://github.com/rasta-mouse/TikiTorch)

[Phantom-Evasion](https://github.com/oddcod3/Phantom-Evasion)

[shellsploit-framework](https://github.com/vasco2016/shellsploit-framework)

### 2. 混淆

#### 2.1 Powershell

[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

[unicorn](https://github.com/trustedsec/unicorn)：PowerShell降级攻击、shellcode直接注入内存的工具

[Invoke-CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter)

[DKMC](https://github.com/Mr-Un1k0d3r/DKMC)：将Powershell shellcode存储在图像中，使得图像和powershell均能使用

[Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage)

[PS_obfs](https://github.com/Mil4n0/PS_obfs)

#### 2.2 Cmd

[Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)

#### 2.3 Vba

[macro_pack](https://github.com/sevagas/macro_pack)

[ViperMonkey](https://github.com/decalage2/ViperMonkey)：分析和反混淆Microsoft Office文件中包含的恶意VBA宏

[EvilClippy](https://github.com/outflanknl/EvilClippy)

[VBad](https://github.com/Pepitoh/VBad)

#### 2.4 Go

[gobfuscate](https://github.com/unixpickle/gobfuscate)

#### 2.5 Python

[Intensio-Obfuscator](https://github.com/Hnfull/Intensio-Obfuscator)

#### 2.6 C#

[self-morphing-csharp-binary](https://github.com/bytecode77/self-morphing-csharp-binary)

[obfuscar](https://github.com/obfuscar/obfuscar)

#### 2.7 Bash

[Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)

[bashfuck](https://github.com/0xddaa/bashfuck)

#### 2.8 Other

[Graffiti](https://github.com/Ekultek/Graffiti)：支持：Python、Perl、Batch、Powershell、PHP、Bash等语言，多重编码方式

[metame](https://github.com/a0rtega/metame)：对exe进行简单的变形

[SCT-obfuscator](https://github.com/Mr-Un1k0d3r/SCT-obfuscator)


### 3. 证书

[apostille](https://github.com/sensepost/apostille)

```
apt install -y maven default-jdk git

git clone https://github.com/sensepost/apostille

cd apostille/

Mvn package

java -jar target/apostille-1.0-SNAPSHOT.jar google.com:443 

tempkeystore.jks kspassword keypassword
```

[SigThief](https://github.com/secretsquirrel/SigThief)

```
1.从二进制文件中获取签名，添加到另一个二进制文件中：./sigthief.py -i consent.exe -t meterpreter.exe -o /tmp/msf_consent.exe

2.保存签名供以后使用：./sigthief.py -i tcpview.exe -r 

3.使用保存的签名：./sigthief.py -s tcpview.exe_sig -t x86_meterpreter_stager.exe 

4.检查是否有签名：./sigthief.py -i tcpview.exe -c 

```
[metatwin](https://github.com/threatexpress/metatwin)

```
c:> powershell -ep bypass

PS> Import-Module c:\tools\metatwin.ps1

PS> cd c:\tools\metatwin\

PS> Invoke-MetaTwin -Source c:\windows\system32\netcfgx.dll -Target .\beacon.exe -Sign

```

[CarbonCopy](https://github.com/paranoidninja/CarbonCopy)：`python3 CarbonCopy.py www.google.com 443 msf.exe google.exe`

[Random-CSharpTools](https://github.com/xorrior/Random-CSharpTools)：`SigPirate.exe -s consent.exe -d meterpreter.exe -o msf_consent.exe -a`


### 4. 执行

#### 4.1 LOLBAS

[GreatSCT](https://github.com/GreatSCT/GreatSCT)：白名单绕过辅助MSF payload执行框架

[PowerShdll](https://github.com/p3nt4/PowerShdll)：使用rundll32.exe，installutil.exe，regsvcs.exe，regasm.exe，regsvr32.exe来运行ps脚本

#### 4.2 Launder

* C#

[AVIator](https://github.com/Ch0pin/AVIator)

[CSharpScripts](https://github.com/Arno0x/CSharpScripts)

[CSharpSetThreadContext](https://github.com/djhohnstein/CSharpSetThreadContext)

[SharpCradle](https://github.com/anthemtotheego/SharpCradle)

* C/C++

[shellcode_launcher](https://github.com/clinicallyinane/shellcode_launcher)：将shellcode加载到内存，从而躲避查杀

[Cooolis-ms](https://github.com/Rvn0xsy/Cooolis-ms)

* Java/Jar

[CoffeeShot](https://github.com/MinervaLabsResearch/CoffeeShot)：将shellcode写入jar注入到指定32位进程，需要java环境

* Powershell

[PowerLine](https://github.com/fullmetalcache/PowerLine)

[PowerShdll](https://github.com/p3nt4/PowerShdll)

[nopowershell](https://github.com/bitsadmin/nopowershell)

[MSBuildShell](https://github.com/Cn33liz/MSBuildShell)

#### 4.3 Other

[CheckPlease](https://github.com/Arvanaghi/CheckPlease)

[UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)

[DotNetToJScript](https://github.com/tyranid/DotNetToJScript)

[AMSI_Handler](https://github.com/two06/AMSI_Handler)

[netrefject](https://github.com/ashr/netrefject)

[SysWhispers](https://github.com/jthuraisamy/SysWhispers)

### 5. 隐藏

[libprocesshider](https://github.com/gianlucaborello/libprocesshider)：Linux下隐藏进程

## Persistence

### 1. dll 劫持

[rattler](https://github.com/sensepost/rattler)

[Robber](https://github.com/MojtabaTajik/Robber)

[SharpGen](https://github.com/cobbr/SharpGen)

[DLL_Hijacker](https://github.com/zhaoed/DLL_Hijacker)

### 2. webshell 生成&管理工具

[weevely3](https://github.com/epinna/weevely3)

[webshell-venom](https://github.com/yzddmr6/webshell-venom)：生成免杀webshell

[Blade](https://github.com/wonderqs/Blade)

[tinyshell](https://github.com/threatexpress/tinyshell)

[WeBaCoo](https://github.com/anestisb/WeBaCoo)：PHP shell连接工具，隐藏在cookie中

[SharPyShell](https://github.com/antonioCoco/SharPyShell)

### 3. 其他

[Vegile](https://github.com/Screetsec/Vegile)：持久化控制的工具，不死后门，杀死再生成

[tsh](https://github.com/orangetw/tsh)

[thetick](https://github.com/nccgroup/thetick)：Linux 后门


## Privilege_Escalation

[Vulmap](https://github.com/vulmon/Vulmap)：在线本地漏洞扫描程序，从Vulmon获取实时漏洞数据，使用这种方法甚至可以检测到最新的漏洞

[BoomER](https://github.com/Josue87/BoomER)：检测和利用本地漏洞

[RedGhost](https://github.com/d4rk007/RedGhost)：支持各种语言的反向shell、sudo inject、contab、提权、CheckVM、收集信息、内存中执行bash脚本、BanIP等

* Bypass-UAC

[UACME](https://github.com/hfiref0x/UACME)

[golang-uacbypasser](https://github.com/0x9ef/golang-uacbypasser)

[alpc-mmc-uac-bypass](https://github.com/DimopoulosElias/alpc-mmc-uac-bypass)


## Credential_Access

### 1. 系统密码

[LaZagne](https://github.com/AlessandroZ/LaZagne)

[SharpWeb](https://github.com/djhohnstein/SharpWeb)

[mimikittenz](https://github.com/putterpanda/mimikittenz)

[Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)：在不触及LSASS的情况下获取NTLM Hash

[mimipenguin](https://github.com/huntergregal/mimipenguin)：Linux有版本限制，需要root权限，仅支持桌面版

[rdp-file-password-encryptor](https://github.com/RedAndBlueEraser/rdp-file-password-encryptor)

[spraykatz](https://github.com/aas-n/spraykatz)：远程procdump解析转储


### 2. 其他密码

[Brute_Force](https://github.com/Matrix07ksa/Brute_Force)：爆破Gmail Hotmail Twitter Facebook Netflix 等账号密码

### 3. Keylogger

[Radium-Keylogger](https://github.com/mehulj94/Radium-Keylogger)

[pykeylogger](https://github.com/amoffat/pykeylogger)

[ceylogger](https://github.com/cheetz/ceylogger)

## Discovery

### 1. 本地信息搜集

[pyHAWK](https://github.com/MetaChar/pyHAWK)：查找本地中的敏感文件,如数据库密码、秘钥文件等

* Linux

[LinuxCheck](https://github.com/al0ne/LinuxCheck)

[GScan](https://github.com/grayddq/GScan)

[linux-explorer](https://github.com/intezer/linux-explorer)

### 2. 网络环境

* 网络拓扑结构

[leprechaun](https://github.com/vonahi-security/leprechaun)：通过netstat显示拓扑结构

[netstat2neo4j](https://github.com/trinitor/netstat2neo4j)：通过netstat命令导出文件显示拓扑结构

[BloodHound](https://github.com/BloodHoundAD/BloodHound)：在域控上执行`SharpHound.exe -c all`，将生成文件导入BloodHound 显示拓扑


### 3. 内网服务&端口探测&漏洞检测

[F-NAScan-PLUS](https://github.com/PINGXcpost/F-NAScan-PLUS)

[LNScan](https://github.com/sowish/LNScan)

[Perun](https://github.com/WyAtu/Perun)

[AssetScan](https://github.com/JE2Se/AssetScan)

[xunfeng](https://github.com/ysrc/xunfeng)

[Ladon](https://github.com/k8gege/Ladon)

[SecurityManageFramwork](https://github.com/zhaoweiho/SecurityManageFramwork)


## Lateral_Movement

### 1. 代理工具

[inlets](https://github.com/alexellis/inlets)

[Venom](https://github.com/Dliv3/Venom)

[hershell](https://github.com/lesnuages/hershell)

[frp](https://github.com/fatedier/frp)

[nps](https://github.com/cnlh/nps)

[ptunnel-ng](https://github.com/lnslbrty/ptunnel-ng)：icmp隧道

### 2. 字典生成器

[CeWL](https://github.com/digininja/CeWL)：kali中自带的工具，可以根据目标网站生成字典

### 3. 弱密码检查&密码爆破

[DBScanner](https://github.com/se55i0n/DBScanner)：自动扫描内网中一些存在未授权访问的数据库，爆破

[F-Scrack](https://github.com/y1ng1996/F-Scrack)：针对FTP、MYSQL、MSSQL、MONGODB、REDIS、TELNET、ELASTICSEARCH、POSTGRESQL 爆破

[fenghuangscanner](https://github.com/she11c0der/fenghuangscanner)：扫描内网中弱口令，LDAP、SMB、redis、MSSQL等

[RDPassSpray](https://github.com/xFreed0m/RDPassSpray)：RDP 爆破工具

### 4. 远程执行命令

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

[SharpExec](https://github.com/anthemtotheego/SharpExec)

[smbmap](https://github.com/ShawnDEvans/smbmap)

[impacket](https://github.com/SecureAuthCorp/impacket)

### 5. NTLM中继&中间人

[NetRipper](https://github.com/NytroRST/NetRipper)

[Responder](https://github.com/SpiderLabs/Responder)

[Inveigh](https://github.com/Kevin-Robertson/Inveigh)

[mitm6](https://github.com/fox-it/mitm6)

[evilgrade](https://github.com/infobyte/evilgrade)

### 6. 其他的一些

[Seth](https://github.com/SySS-Research/Seth)：RDP欺骗

[RDPInception](https://github.com/mdsecactivebreach/RDPInception)：RDP反打客户端


## Command & Control

### 1. DNS

[dnscat2](https://github.com/iagox86/dnscat2)

[powercat](https://github.com/besimorhino/powercat)

[ExternalC2](https://github.com/ryhanson/ExternalC2)

[DoHC2](https://github.com/SpiderLabs/DoHC2)

[goDoH](https://github.com/sensepost/goDoH)

[Slackor](https://github.com/Coalfire-Research/Slackor)

[chashell](https://github.com/sysdream/chashell)

[iodine](https://github.com/yarrick/iodine)

### 2. Wmi&WinRM

[WmiSploit](https://github.com/secabstraction/WmiSploit)

[WMImplant](https://github.com/ChrisTruncer/WMImplant)

[WMIOps](https://github.com/ChrisTruncer/WMIOps)

[evil-winrm](https://github.com/Hackplayers/evil-winrm)

[shell-plus](https://github.com/0nise/shell-plus)

### 3. HTTP&Website

[revbshell](https://github.com/bitsadmin/revbshell)：过杀软

[ThunderShell](https://github.com/Mr-Un1k0d3r/ThunderShell)

[HRShell](https://github.com/chrispetrou/HRShell)

[Octopus](https://github.com/mhaskar/Octopus)

[merlin](https://github.com/Ne0nd0g/merlin)：跨平台，用golang编写的代理,客户端不免杀

[Powershell-C2](https://github.com/enigma0x3/Powershell-C2)

[trevorc2](https://github.com/trustedsec/trevorc2)

[WSC2](https://github.com/Arno0x/WSC2)

[WebDavC2](https://github.com/Arno0x/WebDavC2)

[PoshC2_python](https://github.com/nettitude/PoshC2_python)

### 4. ICMP

[icmpsh](https://github.com/inquisb/icmpsh)

[icmptunnel](https://github.com/DhavalKapil/icmptunnel)

[icmp_tunnel_ex_filtrate](https://github.com/NotSoSecure/icmp_tunnel_ex_filtrate)

[prism](https://github.com/andreafabrizi/prism)

### 5. Image

[C2](https://github.com/et0x/C2)

[Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage)

### 6. Browser

[Browser-C2](https://github.com/0x09AL/Browser-C2)

### 7. Social_Account

[twittor](https://github.com/PaulSec/twittor)

[gcat](https://github.com/byt3bl33d3r/gcat)

[gdog](https://github.com/maldevel/gdog)：比Gcat更厉害，物理位置定位、加密通信、键盘记录

[DBC2](https://github.com/Arno0x/DBC2)

[DropboxC2C](https://github.com/0x09AL/DropboxC2C)

[wikipedia-c2](https://github.com/dweezy-netsec/wikipedia-c2)

[C2-Blockchain](https://github.com/geek-repo/C2-Blockchain)：区块链C2

[TrelloC2](https://github.com/securemode/TrelloC2)：利用Trello分发命令

### 8. Powershell&JavaScript

[PoshC2](https://github.com/nettitude/PoshC2)

[PoshC2_Python](https://github.com/nettitude/PoshC2_Python)

[Covenant](https://github.com/cobbr/Covenant)

[MyJSRat](https://github.com/Ridter/MyJSRat)

[Javascript-Backdoor](https://github.com/3gstudent/Javascript-Backdoor)

### 9. MacOS

[sliver](https://github.com/BishopFox/sliver)

[Apfell](https://github.com/its-a-feature/Apfell)

[MacShellSwift](https://github.com/cedowens/MacShellSwift)

### 10. Other

[koadic](https://github.com/zerosum0x0/koadic)

[redsails](https://github.com/BeetleChunks/redsails)

[Ares](https://github.com/sweetsoftware/Ares)

[bt2](https://github.com/blazeinfosec/bt2)

[SlackShell](https://github.com/bkup/SlackShell)

[RAT-via-Telegram](https://github.com/Dviros/RAT-via-Telegram)

[BrainDamage](https://github.com/mehulj94/BrainDamage)

[spykey](https://github.com/thelinuxchoice/spykey)

[SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY)

[Nuages](https://github.com/p3nt4/Nuages)

[FruityC2](https://github.com/xtr4nge/FruityC2)

[FudgeC2](https://github.com/Ziconius/FudgeC2)

[redViper](https://github.com/itsKindred/redViper)

[C3](https://github.com/mwrlabs/C3)

[proton](https://github.com/entynetproject/proton)

[pocsuite3](https://github.com/knownsec/pocsuite3)

### 11 Rat

[AhMyth-Android-RAT](https://github.com/AhMyth/AhMyth-Android-RAT)

[SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT)

[koadic](https://github.com/zerosum0x0/koadic)

[QuasarRAT](https://github.com/quasar/QuasarRAT)

[pupy](https://github.com/n1nj4sec/pupy)

[RAT-Hodin-v1.0](https://github.com/Thibault-69/RAT-Hodin-v1.0)

[AsyncRAT-C-Sharp](https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp)

[GoMet](https://github.com/gomet-app/GoMet)

[EvilOSX](https://github.com/Marten4n6/EvilOSX)

[CinaRAT](https://github.com/wearelegal/CinaRAT)

[BlackHole](https://github.com/hussein-aitlahcen/BlackHole)

[RedPeanut](https://github.com/b4rtik/RedPeanut)

[Covenant](https://github.com/cobbr/Covenant)

## Exfiltration

[pown-duct](https://github.com/pownjs/pown-duct)

[IPv6teal](https://github.com/christophetd/IPv6teal)

## Misc

### 安全检查

* Webshell-Check

[shellsum](https://github.com/ManhNho/shellsum)：本地webshell检测工具，通过hash枚举

[cloudwalker](https://github.com/chaitin/cloudwalker)

* 监控

[malcom](https://github.com/tomchop/malcom)：监控软件和链接IP

[BLUESPAWN](https://github.com/ION28/BLUESPAWN)

[rita](https://github.com/activecm/rita)

[WatchAD](https://github.com/0Kee-Team/WatchAD)：AD入侵检测系统

[ahrid](https://github.com/gh0stkey/ahrid)：黑客画像工具

* 分析系统

[rifiuti2](https://github.com/abelcheung/rifiuti2)：垃圾箱分析工具

[HaboMalHunter](https://github.com/Tencent/HaboMalHunter)：哈珀病毒分析系统

[antispy](https://github.com/mohuihui/antispy)

* 日志、内存取证

[automactc](https://github.com/CrowdStrike/automactc)：Mac 取证工具

[LogonTracer](https://github.com/JPCERTCC/LogonTracer)：Windows 日志分析工具

### 安全防御

* 蜜罐

[kippo](https://github.com/desaster/kippo)：SSH 蜜罐

[HFish](https://github.com/hacklcx/HFish)：支持HTTP、SSH、SFTP、Redis、Mysql等钓鱼方式，图形化

[awesome-honeypots](https://github.com/paralax/awesome-honeypots/blob/master/README_CN.md)： 各种优秀蜜罐列表

* 防火墙

[sqlassie](https://github.com/super-l/sqlassie)：数据库防火墙

* WAF

[ModSecurity](https://github.com/SpiderLabs/ModSecurity)



