<h2>INTRODUCTION</h2>

Nous vous avons présenté au fil de ces derniers mois les outils **Wazuh** et **Tracecat**, ainsi que différentes manières de les combiner pour réaliser une détection efficace.

*Mais comment pourrions-nous mieux gérer les différentes alertes et en conserver un historique ?*

Dans cet article, nous allons vous montrer comment **automatiser la création de tickets** afin de mieux suivre les alertes et la progression de la réponse à celles-ci.

&nbsp;

<h3>SOMMAIRE</h3>

- [Pré-requis](#PRÉ-REQUIS)

- [Intégrer Wazuh à Tracecat](#INTÉGRER-WAZUH-À-TRACECAT)

- [Automatiser le ticketing](#AUTOMATISER-LE-TICKETING)

- [Pour finir](#POUR-FINIR)

<a name="PRÉ-REQUIS"></a>
&nbsp;

---

<h3>PRÉ-REQUIS</h3>

- Serveur Wazuh (latest:[4.12.0](https://github.com/wazuh/wazuh/releases/tag/v4.12.0))
- Serveur Tracecat (latest:[0.34.3](https://github.com/TracecatHQ/tracecat/releases/tag/0.34.3))

<a name="INTÉGRER-WAZUH-À-TRACECAT"></a>
&nbsp;

---

<h3>INTÉGRER WAZUH À TRACECAT</h3>

Bien, commençons. Tout d'abord, nous avons besoin d'envoyer notre flux d'alertes à **Tracecat**. Nous allons donc passer par un **webhook**.

&nbsp;

<h5>Serveur Wazuh</h5>

Nous allons, dans un premier temps, créer et écrire dans le fichier `/var/ossec/integrations/custom-tracecat.py`.

Ce script nous servira à envoyer nos alertes au format **JSON** vers un **webhook**.

```python
#!/usr/bin/env python3

import sys
import json
import requests
from requests.auth import HTTPBasicAuth

alert_file = open(sys.argv[1])
user = sys.argv[2].split(':')[0]
hook_url = sys.argv[3]

alert_json = json.loads(alert_file.read())
alert_file.close()

alert_level = alert_json['rule']['level']
ruleid = alert_json['rule']['id']
description = alert_json['rule']['description']
agentid = alert_json['agent']['id']
agentname = alert_json['agent']['name']

headers = {'content-type': 'application/json'}
issue_data = {
    "data": alert_json
}

response = requests.post(hook_url, data=json.dumps(issue_data), headers=headers)

sys.exit(0)
```
*crédit : mandev0*

Définissez également les différentes permissions :

```bash
chmod 750 custom-tracecat.py
chown root:wazuh custom-tracecat.py
```

Ensuite, nous devons ajouter les lignes ci-dessous dans le fichier `/var/ossec/etc/ossec.conf`.

Dans notre cas, chaque alerte de niveau 12 déclenchera l'exécution du script, qui enverra les données au **webhook** que nous définirons.

```xml
<ossec_config>
<!-- Custom Tracecat Integration -->
  <integration>
    <name>custom-tracecat.py</name>
    <hook_url>target_webhook</hook_url>
    <level>12</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

&nbsp;

<h5>Serveur Tracecat</h5>

Passons maintenant au serveur **Tracecat**.

Nous devons activer le **webhook** de notre **workflow**.

- [ ] 💡 **Remarque :**
Si vous ne vous souvenez plus comment créer un workflow, vous pouvez vous référer aux articles [précédents](https://www.aukfood.fr/automatiser-l-analyse-dune-adresse-ip-via-lapi-cti-de-crowdsec-avec-tracecat/).

![](https://www.aukfood.fr/wp-content/uploads/2025/05/tooglewebhook-1024x373.png)

N'oubliez pas d'ajouter le lien du **webhook** dans `/var/ossec/etc/ossec.conf` de votre serveur **Wazuh**.

<a name="AUTOMATISER-LE-TICKETING"></a>
&nbsp;

---

<h3>AUTOMATISER LE TICKETING</h3>

Nous allons maintenant pouvoir passer au sujet central de cet article.

Lorsque Wazuh enverra les différentes alertes à Tracecat, il faudra définir ces alertes.

Dans cet article, je vais principalement traiter les alertes du groupe **crowdsec**.

&nbsp;

<h5>Mise en place</h5>

Commençons donc par mettre en place notre nœud `reshape` avec comme input :

```yaml
value: ${{ TRIGGER.data.rule.groups }}
```
![](https://www.aukfood.fr/wp-content/uploads/2025/05/stockgroup.png)

Maintenant que le groupe est stocké, je souhaite également stocker l'**@IP** de l'attaquant. Cela me permettra de la récupérer plus facilement plus tard dans les différents nœuds d'action.

&nbsp;

Nous refaisons donc un `reshape` :

```yaml
value: ${{ TRIGGER.data.data.crowdsec.alert.source.ip }}
```

Je souhaite également ajouter une condition d'activation pour ce nœud d'action. Si le groupe n'est pas **CrowdSec**, alors je ne veux pas que le nœud s'exécute.

```xml
${{ 'crowdsec' in ACTIONS.stock_groups.result }}
```

- [ ] 💡 **Remarque :**
N'oubliez pas qu'il existe plusieurs groupes, donc n'hésitez pas à ajouter plusieurs conditions afin de mieux filtrer ce que vous voulez.

![](https://www.aukfood.fr/wp-content/uploads/2025/05/stockip.png)

&nbsp;

On ajoute ensuite un **"Lookup IP Address"**.  
Une fois l'**@IP** stockée, je souhaite récupérer toutes les informations la concernant dans le **[CTI ](https://app.crowdsec.net/cti) de CrowdSec**.

J'en profite également pour vous informer que **Wazuh** a sorti son propre [**CTI**](https://cti.wazuh.com/vulnerabilities/cves) dans la version **4.12.0**.

```yaml
ip_address: ${{ ACTIONS.stock_ip.result }}
```
![](https://www.aukfood.fr/wp-content/uploads/2025/05/lookupipaddress.png)

&nbsp;

Super, nous allons maintenant pouvoir créer notre ticket.

<h5>Création ticket</h5>

Pour ce faire, rien de plus simple : ajoutez `create_case` à la suite de `lookup_ip_address` et renseignez les informations suivantes en **input** :

```yaml
summary: ${{ TRIGGER.data.agent.name }}
description: ${{ TRIGGER.data.data.crowdsec.alert.scenario }}
status: new
priority: unknown
severity: unknown
```

- [ ] 💡 **Remarque :**
Par défaut, je définis en "unknown".

&nbsp;

Également, je crée trois `reshape` : l'un pour récupérer l'état de réputation de l'@ip attaquante, un autre pour le niveau d'alerte et le dernier pour stocker le `case_id` de mon ticket.

```yaml
value: ${{ ACTIONS.lookup_ip_address.result.data.reputation }}
```

```yaml
value: ${{ TRIGGER.data.rule.level }}
```

```yaml
value: ${{ ACTIONS.create_case.result.id }}
```

![](https://www.aukfood.fr/wp-content/uploads/2025/05/troisnoeuds.png)

&nbsp;

Maintenant, nous avons automatisé la création de ticket. Nous allons pouvoir définir le niveau de priorité et de sévérité, ainsi que le statut du ticket. On peut également assigner une personne et exécuter un workflow en fonction du ticket.

![](https://www.aukfood.fr/wp-content/uploads/2025/05/firstcase-1024x865.png)

&nbsp;

<h5>Priorité et Sévérité</h5>

Et si nous automatisions encore plus ? Par exemple, nous allons ajouter un moyen de définir à la fois le niveau de priorité et de sévérité de l'attaque.

&nbsp;

Pour s'y faire, on va se servir des éléments stockés un peu plus haut. La réputation de l'@IP attaquante va définir le niveau de priorité et le niveau de l'alerte défini le niveau de sévérité.

`update_case`:
```yaml
case_id: ${{ ACTIONS.recup_case_id.result }}
priority: "${{ FN.lookup({ 'malicious': 'critical', 'suspicious': 'high', 'known': 'medium', 'unknown': 'low' }, ACTIONS.stock_reputation.result) if ACTIONS.stock_reputation.result in ['malicious', 'suspicious', 'known', 'unknown'] else 'unknown' }}"
severity:
  ${{
    "fatal" if ACTIONS.stock_level.result == 16
    else "critical" if ACTIONS.stock_level.result == 15
    else "high" if ACTIONS.stock_level.result >= 12
    else "medium" if ACTIONS.stock_level.result >= 4
    else "low"
  }}
```
![](https://www.aukfood.fr/wp-content/uploads/2025/05/defineseveritypriority.png)

Nous pouvons maintenant vérifier dans le *Case Management* de Tracecat si tout fonctionne correctement.

![](https://www.aukfood.fr/wp-content/uploads/2025/05/casemanagement-1024x888.png)

On peut maintenant observer que tout fonctionne bien : j'ai bien reçu l'attribution du niveau de priorité et de sévérité.

&nbsp;

<h5>Commentaires</h5>

Bon, tout ça, c'est très bien, mais comment savoir ce que contient une alerte ? Actuellement, nous avons un ticket avec un niveau de priorité et de sécurité, ainsi qu'une description qui nous donne le nom de l'alerte. Cependant, s'il n'y a pas plus d'informations, cela devient un peu plus compliqué de traiter le ticket.

On va donc rajouter un commentaire tout simple qui va nous donner quelques informations en plus.

Dans mes alertes, j'ai plus d'informations concernant l'attaque dans la partie `events[*].meta`.  
Alors, on va faire en sorte de les lire et de les rajouter en commentaire dans notre ticket.

Pour cela, on va avoir besoin de deux choses :
un nœud `map` et un nœud `create_comment`.

`map` :
```yaml
items: ${{ TRIGGER.data.data.crowdsec.alert.events[0].meta }}
python_lambda: "lambda m: m['key'] + ': ' + m['value']"
```

Alors, quelques explications s’imposent sur ce nœud.

Pour commencer, la ligne `items: ${{ TRIGGER.data.data.crowdsec.alert.events[0].meta }}` nous permet d'extraire notre liste d'éléments.

Ensuite, la ligne `python_lambda: "lambda m: m['key'] + ': ' + m['value']"` indique une fonction lambda qui va être appliquée à chaque élément de la liste.  
Elle construit une chaîne de caractères combinant la clé (`key`) et la valeur (`value`) de chaque élément.

Puis, il ne nous reste plus qu’à ajouter le commentaire dans `create_comment`.

```yaml
case_id: ${{ ACTIONS.recup_case_id.result }}
content: ${{ FN.join(ACTIONS.map.result, '\n- ') }}
```

![](https://www.aukfood.fr/wp-content/uploads/2025/05/commentcase.png)

On peut ensuite constater que nous récupérons bien le commentaire.

![](https://www.aukfood.fr/wp-content/uploads/2025/05/affichecomment.png)

<a name="POUR-FINIR"></a>
&nbsp;

---

<h3>POUR FINIR</h3>

Nous avons vu dans cet article comment créer un workflow pour automatiser la création de tickets à partir de nos alertes Wazuh.
Cette intégration facilite la gestion des alertes ainsi que leur visibilité.

Nous vous avons montré un exemple, mais c’est à vous de l’adapter en fonction de vos alertes.  
N’hésitez pas à ajouter des conditions : vous pouvez en cumuler plusieurs afin de mieux cibler les alertes.

Si vous souhaitez découvrir à la fois Tracecat et Wazuh, voici leurs sites :
- Wazuh : https://wazuh.com
- Tracecat : https://www.tracecat.com
