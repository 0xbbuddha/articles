<h2>INTRODUCTION</h2>

Il y a quelques semaines, CrowdSec a annoncé un nouvel outil nommé **IPDEX**. Qu'est-ce que **IPDEX** ? Comment l'utiliser ? Eh bien, c'est ce que nous allons découvrir dans cet article.

&nbsp;

<h3>SOMMAIRE</h3>

- [Pré-requis](#PRÉ-REQUIS)

- [Installation](#INSTALLATION)

- [Configuration](#CONFIGURATION)

- [Command](#COMMAND)

- [Conclusion](#CONCLUSION)

<a name="PRÉ-REQUIS"></a>
&nbsp;

<h3>PRÉ-REQUIS</h3>
- Une machine avec Go 1.24 ou une version supérieure installé.
- Le dossier GOPATH/bin ou la variable GOBIN doit être ajouté au PATH de votre système pour pouvoir exécuter le binaire depuis n’importe où.

<a name="INSTALLATION"></a>
&nbsp;

<h3>INSTALLATION</h3>

Avant de commencer et de voir les commandes de base, installons IPDEX. Pour cela, rien de plus simple :

```bash
go install github.com/crowdsecurity/ipdex/cmd/ipdex@latest
```
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Super, **IPDEX** vient d’être **installé**.

<a name="CONFIGURATION"></a>
&nbsp;

<h3>CONFIGURATION</h3>

Avant de pouvoir utiliser **IPDEX**, il faut renseigner une clé API pour le **CTI** de **CrowdSec** :

```bash
ipdex init
```
```bash
#output
You can generate an API key in the CrowdSec Console
→ "https://app.crowdsec.net/settings/cti-api-keys"

? Enter your API <api-key>

✅ API Key saved.

🎉 Congratulations! You've just setup ipdex, you can now scan your first IP or your first file!
→ ipdex 1.2.3.4
→ ipdex ips.txt

When scanning files, ipdex will create a new report
→ ipdex ips.txt  # to scan a file
→ ipdex /var/log/nginx/access.log  # to scan a NGINX access log file

IPs result from CrowdSec CTI API are cached for 48h.
→ ipdex 1.2.3.4 -r  # refresh IP cache
→ ipdex ips.txt -r  # refresh all IPs cache from report

CrowdSec quota for free tier is 30 requests/week
→ Everytime you will scan a file that contains more than 30 IPs, you will get a warning
→ ipdex config set --min-ips-warning 500  # to increase minimum of IPs warning

🎮 ipdex initialized! 🎮
```

Ou bien utilisez cette commande :

```bash
ipdex config set --api-key <api-key>
```

Une fois votre clé API **configurée**, vous allez pouvoir utiliser **IPDEX**.

<a name="COMMAND"></a>
&nbsp;

<h3>COMMAND</h3>

Je vais vous présenter quelques commandes que vous allez pouvoir utiliser afin de vous transformer en vrai Sherlock Holmes.

Premièrement, la commande classique : je rajoute le -d pour obtenir plus de détails.

```bash
> ipdex -d 206.189.93.183

IP Information

IP                       	206.189.93.183
Reputation               	malicious
Confidence               	high
Country                  	SG 🇸🇬
Autonomous System        	DIGITALOCEAN-ASN
Reverse DNS              	N/A
Range                    	206.189.0.0/16
First Seen               	2025-05-24T10:15:00
Last Seen                	2025-05-26T09:30:00
Console URL              	https://app.crowdsec.net/cti/206.189.93.183
Last Local Refresh       	2025-05-26 11:55:51

Threat Information

Behaviors                	
                         	HTTP Exploit
                         	HTTP DoS
                         	Exploitation attempt
                         	HTTP Scan
                         	HTTP Bruteforce

Classifications          	
                         	Spoofed User Agent
                         	CrowdSec Community Blocklist

Exploiting CVEs          	
                         	CVE-2017-9841

Target countries         	
     🇫🇷 FR             		31%
     🇩🇪 DE             		19%
     🇺🇸 US             		18%
     🇨🇦 CA             		5%
     🇭🇺 HU             		5%
```

Vous pouvez également scanner des fichiers de log, par exemple :

```bash
> ipdex nextcloud.log 
Enriching with CrowdSec CTI: 109.69.110.221 [309/309] ████████████████ 100% | 0s

General

Report ID                	2
Report Name              	Thunder-Photon-Report
Creation Date            	2025-05-16 16:02:53
File path                	/home/ipdex/nextcloud.log
SHA256                   	1556bdb886ad84a89b525f98faa812c4783ef82693a2311de9dcdc12d81d3c76
Number of IPs            	309
Number of known IPs      	170 (55%)

Stats

🌟 Top Reputation         	
     Unknown                                         		139 (45%)
     Known                                           		119 (39%)
     Suspicious                                      		22 (7%)
     Malicious                                       		19 (6%)
     Safe                                            		7 (2%)

🗂️ Top Classifications   	
     CrowdSec Community Blocklist                    		17 (6%)
     SEO crawler                                     		7 (2%)
     Spoofed User Agent                              		4 (1%)
     Public Internet Scanner                         		3 (1%)
     Known Security Company: Censys                  		2 (1%)

🤖 Top Behaviors          	
     HTTP Scan                                       		129 (42%)
     HTTP Bruteforce                                 		119 (39%)
     POP3/IMAP Bruteforce                            		81 (26%)
     HTTP Exploit                                    		67 (22%)
     HTTP Crawl                                      		43 (14%)

⛔ Top Blocklists         	
     Mail Server Attackers                           		18 (6%)
     CrowdSec Intelligence Blocklist                 		18 (6%)
     High Background Noise                           		13 (4%)
     Targeted Country: France                        		8 (3%)
     Retail and Ecommerce Attackers                  		5 (2%)

💥 Top CVEs               	
     CVE-2021-41714                                  		2 (1%)
     CVE-2019-17050                                  		2 (1%)
     CVE-2017-16894                                  		2 (1%)
     CVE-2020-11738                                  		1 (0%)
     CVE-2024-4040                                   		1 (0%)

🌐 Top IP Ranges          	
     unknown                                         		139 (45%)
     92.184.96.0/19                                  		72 (23%)
     66.249.64.0/19                                  		6 (2%)
     176.144.0.0/12                                  		6 (2%)
     37.64.0.0/13                                    		5 (2%)

🛰️ Top Autonomous Systems	
     unknown                                         		139 (45%)
     Orange                                          		75 (24%)
     Bouygues Telecom SA                             		16 (5%)
     MICROSOFT-CORP-MSN-AS-BLOCK                     		11 (4%)
     PacketHub S.A.                                  		10 (3%)

🌎 Top Countries          	
     unknown 🏳️                                      		139 (45%)
     FR 🇫🇷                                           		131 (42%)
     US 🇺🇸                                           		13 (4%)
     NL 🇳🇱                                           		6 (2%)
     CH 🇨🇭                                           		5 (2%)
```

Et pour finir, vous pouvez également effectuer des recherches en fonction, par exemple, d’un reverse DNS en particulier, d’une CVE, d’une localisation, e.t. :

```bash
.> ipdex search reverse_dns:"<reverse_dns>"
 SUCCESS  Fetching complete!                                                                                                                                      

General

Report ID                	3
Report Name              	Atlas-Blaze-Report
Creation Date            	2025-05-26 12:03:11
Query                    	reverse_dns:"<reverse_dns>"
Since Duration           	30d
Since Time               	2025-04-26 12:03:11
Number of IPs            	1
Number of known IPs      	1 (100%)

Stats

🌟 Top Reputation         	
     Known                                           		1 (100%)
     Unknown                                         		0 (0%)


🤖 Top Behaviors          	
     HTTP Bruteforce                                 		1 (100%)
     HTTP Crawl                                      		1 (100%)



🌐 Top IP Ranges          	
     82.96.128.0/18                                  		1 (100%)
     unknown                                         		0 (0%)

🛰️ Top Autonomous Systems	
     Free Pro SAS                                    		1 (100%)
     unknown                                         		0 (0%)

🌎 Top Countries          	
     FR 🇫🇷                                           		1 (100%)
     unknown 🏳️                                      		0 (0%)
```
<a name="CONCLUSION"></a>
&nbsp;

<h3>CONCLUSION</h3>

Voilà, vous avez découvert IPDEX, un outil super pratique. N’hésitez pas à explorer encore d’autres options et à l’utiliser sans modération !

github : https://github.com/crowdsecurity/ipdex
