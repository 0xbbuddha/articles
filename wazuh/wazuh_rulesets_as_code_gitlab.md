Le concept de **Ruleset as Code (RaC)** appliqué à **Wazuh** apporte une approche **DevOps** permettant d’automatiser et de fiabiliser la gestion des règles de détection et de supervision de la sécurité. Grâce à cette méthode, les équipes peuvent tirer parti des systèmes de gestion de versions (Git, par exemple) et des **pipelines CI/CD** pour déployer automatiquement les décodeurs et règles Wazuh.

Inspirée des principes de l’Infrastructure as Code (IaC), cette approche favorise la collaboration entre équipes, le suivi des évolutions, ainsi que la possibilité de revenir facilement à une version antérieure en cas de problème. Elle permet également d’assurer un déploiement continu de la logique de détection, sans nécessiter d’accès direct au **Wazuh Manager**.

Dans ce nouvel article, nous allons explorer concrètement la mise en place de **Wazuh RaC** en utilisant un dépôt [Detection-Engineering as Code (DaC)](https://github.com/0xbbuddha/DaC-Wazuh-Gitlab-setup) dédié. L’objectif est d’automatiser tout le cycle de vie des règles personnalisées  de leur création jusqu’à leur déploiement en s’appuyant sur un pipeline CI/CD.

Un grand merci à [SamsonIdowu](https://github.com/SamsonIdowu), à l’origine du dépôt DaC pour GitHub Actions, sur lequel nous nous sommes appuyés pour construire ce nouveau dépôt DaC adapté à GitLab CI/CD. 
<br>

---

<h3>
Comment ça fonctionne ?
</h3>

Découvrons ensemble comment fonctionne Wazuh RaC, depuis la définition des règles jusqu’à leur mise en production sur le serveur Wazuh.<br>

![](https://www.aukfood.fr/wp-content/uploads/2025/08/RaC-Gitlab-1024x576.png) <br>

1. **Développement et tests en local** : Les ingénieurs en sécurité commencent par concevoir et ajuster les règles directement sur leur machine, en utilisant des outils de développement comme Visual Studio Code. Ils opèrent au sein des répertoires réservés aux règles personnalisées de Wazuh  :

	- `/var/ossec/etc/decoders`
	- `/var/ossec/etc/rules`

	Un dépôt Git local permet de suivre et de gérer les modifications apportées à ces répertoires.

	- [] Note: Nous configurons un fichier `.gitignore` pour exclure les fichiers et dossiers non essentiels dans le répertoire `/var/ossec/etc/`, afin de ne versionner que les ensembles de règles pertinents.
<br>

2. **Envoi vers la branche develop** : Une fois les règles testées localement, elles sont validées et transférées vers une branche develop du dépôt distant (GitLab). Cette branche sert de zone de développement collaborative, permettant à plusieurs ingénieurs en sécurité de travailler ensemble.
<br>

3. **Revue et fusion des modifications** : Les changements apportés à la branche develop font l’objet d’une relecture par les pairs. Une merge request (ou pull request) est créée pour intégrer les mises à jour de la branche dev vers la branche main. Ce processus permet de garantir la qualité du code, de faciliter la collaboration et d’assurer le suivi et l’audit des modifications.
<br>

4. **Fusion vers la branche main et déclenchement du pipeline CI/CD** : Une fois la merge request approuvée et intégrée dans la branche main, le pipeline CI/CD est automatiquement lancé. Le processus s’exécute selon l’ordre suivant :
	- Se rend dans le répertoire `/var/ossec/etc/`, où sont stockés les ensembles de règles.
	- Récupère les dernières modifications des règles depuis le dépôt distant GitLab vers le dépôt local à l’aide de la commande `git pull`.
	- Met à jour le propriétaire et les permissions des fichiers en exécutant les commandes `chown wazuh:wazuh` et `chmod 660`
	- Redémarre le service du gestionnaire Wazuh et affiche un message de *succès* si le redémarrage s’effectue correctement, ou un message d’*échec* en cas de problème..
	- Pour faciliter le débogage, la commande `systemctl status wazuh-manager` est incluse afin de vérifier l’état du gestionnaire Wazuh une fois toutes les opérations terminées.
<br>

5. **Déploiement automatisé vers Wazuh** : Le runner synchronise automatiquement les fichiers de règles mis à jour avec le serveur Wazuh, garantissant que les règles les plus récentes et validées sont appliquées dès que le pipeline CI/CD se termine avec succès. Cette étape supprime toute intervention manuelle, réduit les risques d’erreurs et assure que les environnements Wazuh en production fonctionnent toujours avec des configurations vérifiées.
<br>

---

<h3>
Prérequis
</h3>

- Un serveur Wazuh (v4.12.0) avec Git installé (v2.31)
- Tout poste de travail disposant de l’IDE Visual Studio Code pour créer les ensembles de règles Wazuh.
- Une connexion SSH pour pouvoir récupérer le dépôt distant en local et pousser les modifications.
- Un compte GitLab
<br>

---

<h3>
Configuration
</h3>
<br>

<h4>
SSH connexion
</h4>

Si ce n’est pas déjà fait, n’oubliez pas de créer votre clé SSH afin de pouvoir récupérer et pousser les modifications.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/rac
```

<h4>
Server Wazuh
</h4>

Si votre serveur Wazuh est derrière un pare-feu, n’oubliez pas d’autoriser l’@ip du GitLab runner.

<h4>
Création du dépôt distant GitLab
</h4>

Pour synchroniser les modifications locales avec celles distantes, nous allons mettre en place et utiliser un dépôt Git.

Afin de versionner les répertoires personnalisés de règles Wazuh (`/var/ossec/etc/decoders` et `/var/ossec/etc/rules`), nous mettons en place un dépôt Git local. Le répertoire `/var/ossec/etc/` est initialisé comme dépôt Git, tandis que les autres fichiers et répertoires sont exclus grâce à un fichier .gitignore.

<h4>
Dépôt distant
</h4>

Le dépôt [DaC](https://github.com/0xbbuddha/DaC-Wazuh-Gitlab-setup) contient les fichiers de workflow nécessaires pour automatiser l’intégration et la mise à jour des règles sur votre serveur Wazuh. Il inclut également un script qui vérifie les conflits d’identifiants de règles afin de prévenir toute erreur sur le serveur.

Vous pouvez soit forker ce dépôt, soit créer un nouveau dépôt sur GitLab, puis y importer le contenu du dépôt DaC.

- `.gitlab/ci/scripts/integrate_rulesets.sh` : Ce fichier contient le workflow Update Rulesets on SIEM, qui automatise l’intégration des décodeurs et règles personnalisés, nouveaux ou modifiés, avec le serveur Wazuh.

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${WAZUH_HOST:?Missing WAZUH_HOST variable}"
: "${WAZUH_USER:?Missing WAZUH_USER variable}"
WAZUH_SSH_PORT=${WAZUH_SSH_PORT:-22}
REPO_DIR=${REPO_DIR:-/var/ossec/etc}
WAZUH_RESTART_CMD=${WAZUH_RESTART_CMD:-"sudo systemctl restart wazuh-agent"}
SSH_STRICT=${SSH_STRICT:-"no"}

echo "==> Preparing SSH key"
mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [[ -z "${WAZUH_SSH_PRIVATE_KEY:-}" ]]; then
  echo "[ERROR] WAZUH_SSH_PRIVATE_KEY not defined in CI variables."
  exit 2
fi

echo "$WAZUH_SSH_PRIVATE_KEY" > ~/.ssh/id_ed25519
chmod 600 ~/.ssh/id_ed25519

if [[ -n "${WAZUH_HOST_FINGERPRINT:-}" ]]; then
  echo "${WAZUH_HOST_FINGERPRINT}" >> ~/.ssh/known_hosts
else
  if [[ "$SSH_STRICT" == "yes" ]]; then
    echo "[ERROR] SSH_STRICT=yes but WAZUH_HOST_FINGERPRINT is missing."
    exit 3
  fi
  echo "==> Strict verification disabled (automatic host key scanning)"
fi

SSH_OPTS=(
  -p "$WAZUH_SSH_PORT"
  -o StrictHostKeyChecking=${SSH_STRICT}
  -o UserKnownHostsFile=~/.ssh/known_hosts
)

echo "==> Pulling GitHub repository into ${REPO_DIR}"
ssh -i ~/.ssh/id_ed25519 ${SSH_OPTS[*]} "${WAZUH_USER}@${WAZUH_HOST}" "cd ${REPO_DIR} && git pull"

echo "==> Restarting Wazuh service"
ssh -i ~/.ssh/id_ed25519 ${SSH_OPTS[*]} "${WAZUH_USER}@${WAZUH_HOST}" "$WAZUH_RESTART_CMD"

echo "==> Update completed"
```
<br>

- `.gitlab/ci/scripts/check_rule_ids.sh` : Ce fichier définit un workflow qui exécute automatiquement le script `check_rule_ids.py` afin de détecter d’éventuels conflits entre les identifiants de règles.

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "==> Checking rule IDs via check_rule_ids.py"

if [[ ! -f "check_rule_ids.py" ]]; then
  echo "[ERROR] check_rule_ids.py file not found at the root of the repository"
  exit 2
fi

python -m pip install --upgrade pip >/dev/null 2>&1 || true
python -m pip install lxml >/dev/null 2>&1 || true

python check_rule_ids.py
```
<br>

`.gitlab/ci/scripts/lint_xml.sh` : Ce fichier vérifie la bonne syntaxe des fichiers XML dans vos décodeurs et règles.
```bash
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob
echo "==> Lint XML: decoders/*.xml rules/*.xml"
fail=0
lint_dir() {
  local dir="$1"
  if [[ -d "$dir" ]]; then
    for f in "$dir"/*.xml; do
      if ! xmllint --noout "$f"; then
        echo "[ERROR] xmllint failed: $f"
        fail=1
      else
        echo "[OK] $f"
      fi
    done
  else
    echo "[WARN] Directory not found: $dir"
  fi
}
lint_dir "decoders"
lint_dir "rules"
exit $fail
```
<br>

- `check_rule_ids.py` : Ce script Python permet de détecter les conflits d’ID de règles en comparant les identifiants des règles ajoutées ou modifiées dans la branche develop avec ceux déjà présents dans la branche main.

```python
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import sys
import os
from collections import defaultdict, Counter

def run_git_command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ Git command failed: {' '.join(args)}")
        print(f"Error: {e.stderr}")
        raise

def get_target_branch():
    """Determine the target branch based on the environment"""
    # GitLab CI variables
    if os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME'):
        return f"origin/{os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME')}"
    elif os.getenv('CI_DEFAULT_BRANCH'):
        return f"origin/{os.getenv('CI_DEFAULT_BRANCH')}"
    # Fallback for GitHub or local
    else:
        return "origin/main"

def setup_git_environment():
    """Configure Git for CI environment"""
    if os.getenv('CI'):
        try:
            # Fetch all branches
            run_git_command(["git", "fetch", "origin"])
            # Configure Git user
            run_git_command(["git", "config", "--global", "user.email", "ci@gitlab.com"])
            run_git_command(["git", "config", "--global", "user.name", "GitLab CI"])
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Warning during git setup: {e}")

def get_changed_rule_files():
    target_branch = get_target_branch()
    print(f"🔍 Comparing against: {target_branch}")

    try:
        if os.getenv('CI'):
            run_git_command(["git", "fetch", "origin"])

        # Try different commands depending on environment
        commands_to_try = [
            ["git", "diff", "--name-status", f"{target_branch}...HEAD"],
            ["git", "diff", "--name-status", f"{target_branch}..HEAD"],
            ["git", "diff", "--name-status", target_branch],
            ["git", "diff", "--name-status", "HEAD~1"],
            ["git", "diff", "--name-status", "--cached"],
            ["git", "ls-files", "--others", "--exclude-standard"]
        ]

        output = ""
        for cmd in commands_to_try:
            try:
                print(f"🔄 Trying: {' '.join(cmd)}")
                output = run_git_command(cmd)
                if output.strip():
                    print(f"✅ Command succeeded with output")
                    break
                else:
                    print(f"⚠️ Command succeeded but no output")
            except subprocess.CalledProcessError as e:
                print(f"❌ Command failed: {e}")
                continue

        if not output.strip():
            print("🔄 No changes detected via git diff, checking all XML files in rules/")
            rules_dir = Path("rules")
            if rules_dir.exists():
                xml_files = list(rules_dir.glob("*.xml"))
                changed_files = [("+", f) for f in xml_files]
                print(f"📁 Found XML files: {[f.name for f in xml_files]}")
                return changed_files

        changed_files = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 1:
                file_path = parts[0]
                status = "A"
            elif len(parts) == 2:
                status, file_path = parts
            else:
                continue

            print(f"📄 Processing: {status} {file_path}")
            if file_path.startswith("rules/") and file_path.endswith(".xml"):
                changed_files.append((status, Path(file_path)))

        print(f"📋 Final changed files: {[(s, f.name) for s, f in changed_files]}")
        return changed_files

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to get changed files: {e}")
        sys.exit(1)

def extract_rule_ids_from_xml(content):
    ids = []
    try:
        content = content.strip()
        if not content:
            return ids

        wrapped = f"<root>{content}</root>"
        root = ET.fromstring(wrapped)
        for rule in root.findall(".//rule"):
            rule_id = rule.get("id")
            if rule_id and rule_id.isdigit():
                ids.append(int(rule_id))
    except ET.ParseError as e:
        print(f"⚠️ XML Parse Error: {e}")
    return ids

def get_rule_ids_per_file_in_target():
    target_branch = get_target_branch()

    try:
        run_git_command(["git", "fetch", "origin"])
        files_output = run_git_command(["git", "ls-tree", "-r", target_branch, "--name-only"])
    except subprocess.CalledProcessError:
        print(f"⚠️ Cannot access {target_branch}, using current HEAD")
        files_output = run_git_command(["git", "ls-tree", "-r", "HEAD", "--name-only"])

    xml_files = [f for f in files_output.splitlines() if f.startswith("rules/") and f.endswith(".xml")]

    rule_id_to_files = defaultdict(set)
    for file in xml_files:
        try:
            content = run_git_command(["git", "show", f"{target_branch}:{file}"])
            rule_ids = extract_rule_ids_from_xml(content)
            for rule_id in rule_ids:
                rule_id_to_files[rule_id].add(file)
        except subprocess.CalledProcessError:
            continue
    return rule_id_to_files

def get_rule_ids_from_target_version(file_path: Path):
    target_branch = get_target_branch()
    try:
        content = run_git_command(["git", "show", f"{target_branch}:{file_path.as_posix()}"])
        return extract_rule_ids_from_xml(content)
    except subprocess.CalledProcessError:
        return []

def detect_duplicates(rule_ids):
    counter = Counter(rule_ids)
    return [rule_id for rule_id, count in counter.items() if count > 1]

def print_conflicts(conflicting_ids, rule_id_to_files):
    print("❌ Conflicts detected:")
    for rule_id in sorted(conflicting_ids):
        files = rule_id_to_files.get(rule_id, [])
        print(f"  - Rule ID {rule_id} found in:")
        for f in files:
            print(f"    • {f}")

def main():
    print("🚀 Starting rule ID conflict checker...")
    print(f"Environment: {'GitLab CI' if os.getenv('CI') else 'Local'}")

    print("🐛 Debug info:")
    print(f"CI: {os.getenv('CI')}")
    print(f"CI_MERGE_REQUEST_TARGET_BRANCH_NAME: {os.getenv('CI_MERGE_REQUEST_TARGET_BRANCH_NAME')}")
    print(f"CI_DEFAULT_BRANCH: {os.getenv('CI_DEFAULT_BRANCH')}")
    print(f"CI_COMMIT_REF_NAME: {os.getenv('CI_COMMIT_REF_NAME')}")
    print(f"CI_COMMIT_SHA: {os.getenv('CI_COMMIT_SHA')}")
    print(f"Working directory: {os.getcwd()}")

    rules_dir = Path("rules")
    if rules_dir.exists():
        xml_files = list(rules_dir.glob("*.xml"))
        print(f"📁 XML files in rules/: {[f.name for f in xml_files]}")
    else:
        print("❌ rules/ directory not found!")

    setup_git_environment()

    try:
        git_status = run_git_command(["git", "status", "--porcelain"])
        print(f"📋 Git status: {git_status.strip() if git_status.strip() else 'clean'}")

        branches = run_git_command(["git", "branch", "-a"])
        print(f"🌿 Available branches: {branches.strip()}")

        last_commit = run_git_command(["git", "log", "--oneline", "-1"])
        print(f"📝 Last commit: {last_commit.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Debug git command failed: {e}")

    changed_files = get_changed_rule_files()
    if not changed_files:
        print("⚠️ No rule files detected as changed via git diff.")
        if "--force" in sys.argv or os.getenv('FORCE_CHECK_ALL_RULES'):
            print("🔄 Force checking all XML files in rules/")
            rules_dir = Path("rules")
            if rules_dir.exists():
                xml_files = list(rules_dir.glob("*.xml"))
                changed_files = [("A", f) for f in xml_files]
                print(f"📁 Force checking: {[f.name for f in xml_files]}")

        if not changed_files:
            print("✅ No rule files to check.")
            return

    rule_id_to_files_target = get_rule_ids_per_file_in_target()

    print(f"🔍 Checking rule ID conflicts for files: {[f.name for _, f in changed_files]}")

    for status, path in changed_files:
        print(f"\n🔎 Checking file: {path.name}")

        try:
            if path.exists():
                dev_content = path.read_text(encoding='utf-8')
            else:
                print(f"⚠️ File {path.name} does not exist locally, skipping...")
                continue

            dev_ids = extract_rule_ids_from_xml(dev_content)
        except Exception as e:
            print(f"⚠️ Could not read {path.name}: {e}")
            continue

        duplicates = detect_duplicates(dev_ids)
        if duplicates:
            print(f"❌ Duplicate rule IDs detected in {path.name}: {sorted(duplicates)}")
            sys.exit(1)

        if status == "A":
            conflicting_ids = set(dev_ids) & set(rule_id_to_files_target.keys())
            if conflicting_ids:
                print_conflicts(conflicting_ids, rule_id_to_files_target)
                sys.exit(1)
            else:
                print(f"✅ No conflict in new file {path.name}")

        elif status == "M":
            target_ids = get_rule_ids_from_target_version(path)
            if set(dev_ids) == set(target_ids):
                print(f"ℹ️ {path.name} modified but rule IDs unchanged.")
                continue

            new_or_changed_ids = set(dev_ids) - set(target_ids)
            conflicting_ids = new_or_changed_ids & set(rule_id_to_files_target.keys())

            if conflicting_ids:
                print_conflicts(conflicting_ids, rule_id_to_files_target)
                sys.exit(1)
            else:
                print(f"✅ Modified file {path.name} has no conflicting rule IDs.")

    print("\n✅ All rule file changes passed conflict checks.")

if __name__ == "__main__":
    main()
```
<br>

- `.gitlab-ci.yml` : Sans oublier ce fichier, qui permet d’exécuter le runner avec toutes les tâches que l’on souhaite.

```yml
# GitLab CI pour Ruleset-as-Code

stages:
  - lint
  - verify
  - package
  - deploy

default:
  image: python:3.12-slim
  before_script:
    - apt-get update -y
    - apt-get install -y --no-install-recommends libxml2-utils ca-certificates openssh-client git
    - python --version
  cache:
    paths:
      - .cache/pip

workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH

variables:
  PIP_DISABLE_PIP_VERSION_CHECK: "1"
  PYTHONDONTWRITEBYTECODE: "1"
  PYTHONUNBUFFERED: "1"

xml:lint:
  stage: lint
  script:
    - bash .gitlab/ci/scripts/lint_xml.sh
  artifacts:
    when: always
    reports: {}

python:check_ids:
  stage: verify
  script:
    - bash .gitlab/ci/scripts/check_rule_ids.sh
  needs: ["xml:lint"]
  artifacts:
    when: always
    reports: {}

deploy:wazuh:
  stage: deploy
  script:
    - bash .gitlab/ci/scripts/integrate_rulesets.sh
  needs:
    - xml:lint
    - python:check_ids
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
      when: on_success
      allow_failure: false
    - if: '$CI_COMMIT_TAG'
      when: on_success
      allow_failure: false
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
      when: on_success
      allow_failure: true
  environment:
    name: wazuh
    action: start
```

<h4>
Dépôt local
</h4>

Nous pouvons maintenant effectuer les actions suivantes sur notre serveur Wazuh pour configurer le dépôt Git.

1. Nous nous plaçons dans le répertoire `/var/ossec/etc` qui servira de répertoire de travail :

```bash
cd /var/ossec/etc
```
<br>

2. Nous créons un fichier `.gitignore` dans ce répertoire afin d’exclure de Git tous les fichiers et dossiers qui ne concernent pas les répertoires `decoders/` et `rules/` :

```bash
touch .gitignore
```
<br>

3. Nous ajoutons au fichier `.gitignore` les fichiers et dossiers à ignorer, ainsi que tout autre fichier ou dossier que nous souhaitons exclure de la gestion Git :

```bash
# Ignorer les fichiers suivants
client.keys
internal_options.conf
local_internal_options.conf
ossec.conf
sslmanager.cert
localtime
sslmanager.key

# Ignorer les dossiers suivants
lists/
rootcheck/
shared/
```
<br>

4. Nous marquons le répertoire de travail comme sûr afin de pouvoir l’ajouter à Git :

```bash
git config --global --add safe.directory /var/ossec/etc
```
<br>

5. Nous initialisons le répertoire de travail en tant que dépôt Git. Cette action crée un répertoire `.git` dans notre répertoire de travail :

```bash
git init
```
<br>

6. Nous ajoutons notre dépôt Wazuh RaC comme origin dans Git local, afin de pouvoir envoyer nos modifications locales et récupérer les modifications distantes :

```bash
git remote add origin https://<USERNAME><PERSONAL_ACCESS_TOKEN>@gitlab.com/<PATH>/<REPO_NAME>.git
```
<br>

7. Nous configurons notre identité Git, qui sera utilisée pour signer nos commits locaux :

```bash
git config --global user.name <VOTRE_NOM>
git config --global user.email <VOTRE_ADRESSE_EMAIL>
```
<br>

8. Nous créons une nouvelle branche main et basculons dessus :

```bash
git checkout -b main
```
<br>

9. Nous préparons les fichiers de règles et de décodeurs dans les répertoires `decoders/` et `rules/` pour le commit, puis nous effectuons un premier commit dans le dépôt Git local :

```bash
git add .
git commit -m "feat: initial commit"
```
<br>

10. Nous synchronisons les modifications de notre dépôt local avec la branche main du dépôt distant et nous les envoyons sur GitLab :

```bash
git pull --rebase origin main
git push -u origin main
```

<h4>
Création de la branche develop
</h4>

Pour protéger la branche main, où sont stockés les ensembles de règles les plus stables avant leur déploiement sur le serveur Wazuh, nous devons créer une branche develop. Le développement de nouvelles règles se fait dans cette branche develop afin de permettre une revue et des tests appropriés avant de fusionner les modifications dans la branche main, qui est ensuite déployée en production.

```bash
git checkout -b develop
```

<h4>
Création des variables CI/CD GitLab
</h4>

Pour sécuriser l’exécution des workflows d’automatisation sur GitLab, nous devons créer des variables CI/CD dans le dépôt distant.

1. Dans votre dépôt GitLab, allez dans : `Settings > CI/CD > Variables`
<br>

2. Créez les variables suivantes :
	- **WAZUH_USER** : Nom de l’utilisateur SSH utilisé par les pipelines pour se connecter au serveur Wazuh
	- **WAZUH_HOST** : Adresse du serveur Wazuh où seront déployées les règles via le pipeline
	- **WAZUH_SSH_PRIVATE_KEY** : Clé privée permettant l’authentification sécurisée du pipeline lors des connexions SSH au serveur Wazuh

![](https://www.aukfood.fr/wp-content/uploads/2025/08/variable_ci-1024x287.png)

- [] Remarque : Nous pouvons également définir d’autres variables selon nos besoins, comme :
	- **WAZUH_SSH_PORT** : Port réseau utilisé pour la connexion SSH, à personnaliser si le serveur n’utilise pas le port par défaut
	- **REPO_DIR** : le chemin du dépôt sur le serveur Wazuh
	- **WAZUH_RESTART_CMD** : la commande pour redémarrer le service Wazuh après le déploiement des règles
	- **SSH_STRICT** : pour activer ou désactiver la vérification stricte de l’authenticité de l’hôte

<h4>
Configuration de VSCode pour visualiser des ensembles de règles
</h4>

Pour consulter nos règles Wazuh depuis VSCode, nous procédons comme suit :

1. Nous ouvrons VSCode, puis nous allons dans Extensions. Nous recherchons l’extension GitLab Workflows et nous l’installons.
<br>

2. Configurez votre token personnel en appuyant sur `Ctrl+Shift+P` et en recherchant `GitLab: Authenticate`.
<br>

3. Ouvrez votre dépôt en appuyant sur Ctrl+Shift+P et en recherchant GitLab: Open Remote Repository.

- [] Note : Il n’est pas encore possible de créer ou de modifier les règles et decoders directement à l’aide de cette extension.
<br>

---

<h3>
Utilisation Wazuh RaC
</h3>

Nous allons voir dans cette section comment réaliser l’ensemble de la procédure pour créer ou modifier vos règles et décodeurs dans Wazuh, depuis la branche de développement jusqu’à l’intégration dans la branche principale.

<h4>
Déploiement d'ensembles de règles/decodeurs sur le serveur Wazuh
</h4>

1. Basculer sur la branche de développement et récupérer les dernières modifications

```bash
git switch develop
git pull origin develop
```
<br>

2. Modifier les fichiers de règles
```bash
# éditer rules/local_rules.xml
```
Nous ajoutons ou modifions les règles dans le fichier approprié, par exemple local_rules.xml.
<br>

3. Préparer les modifications pour le commit

```bash
git add .
```
<br>

4. Créer un commit local

```bash
git commit -m "feat: règle XYZ"
```
Nous enregistrons nos modifications avec un message de commit clair.
<br>

5. Envoyer les modifications sur le dépôt distant

```bash
git push origin develop
```
Nous mettons à jour la branche develop sur le serveur GitLab.
<br>

6. Ne pas oublier de paramétrer l’outil CLI `glab`

```bash
glab auth login
```
<br>

7. Créer une Merge Request (MR) pour fusionner develop → main

```bash
glab mr create --source-branch develop --target-branch main --title "Fusion develop → main : ajout règle XYZ" --description "MR pour intégrer la règle XYZ"
```
<br>

8. Vérifier l’état des pipelines CI/CD

```bash
glab pipeline list
glab pipeline view <ID_DU_PIPELINE>
```
Nous suivons l’exécution des pipelines pour s’assurer que le déploiement des règles se déroule correctement

<h4>
Protection main branche
</h4>

Il reste crucial de protéger notre branche main contre tout commit non souhaité ou toute modification accidentelle pouvant compromettre la stabilité du projet. Pour automatiser cette protection, le dépôt [DaC](https://github.com/0xbbuddha/DaC-Wazuh-Gitlab-setup) inclut le script protect_main.sh.

Ce script se charge de plusieurs tâches importantes :
- Protéger la branche main afin que personne ne puisse y pousser directement sans passer par une Merge Request.
- Configurer les règles de Merge Request, comme l’obligation que le pipeline CI réussisse et que toutes les discussions soient résolues avant de merger.
- Définir les Push Rules, pour contrôler le format des commits, empêcher la suppression de tags et limiter la taille des fichiers.
- Ajouter des règles d’approbation, garantissant qu’au moins un reviewer valide la MR avant son intégration.

Pour que le script fonctionne correctement, certaines variables doivent être configurées manuellement avant son exécution :
- **GITLAB_URL** : l’URL de votre instance GitLab.
- **PROJECT_ID** : l’identifiant du projet.
- **GITLAB_TOKEN** : un token d’accès personnel avec les droits nécessaires pour modifier les paramètres du projet.

En configurant ces variables, vous pouvez lancer protect_main.sh et sécuriser automatiquement votre workflow GitLab, en vous assurant que seules des modifications validées et approuvées seront intégrées dans la branche principale. Cela réduit fortement le risque d’erreurs critiques tout en appliquant des bonnes pratiques de gouvernance du code.
<br>

---

<h3>
Conclusion
</h3>

Wazuh Ruleset as Code (RaC) représente une approche DevOps appliquée à la sécurité et à la création de règles et decodeurs de détection. En considérant les règles/decodeurs comme du code, les équipes de sécurité peuvent gérer, tester et déployer leurs logiques de détection avec la même rigueur et rapidité que les équipes de développement logiciel. Cette méthode favorise des mises à jour plus rapides, limite les erreurs en production et assure une meilleure cohérence des règles de détection des menaces.

Enfin, c’est un immense plaisir pour nous, **Aukfood**, d’avoir mené à bien ce projet et de proposer une alternative à GitHub pour le RaC Wazuh, offrant ainsi une nouvelle façon de gérer et déployer les règles de sécurité de manière collaborative et sécurisée.
<br>

---

<h3>
Références
</h3>

- [Wazuh Ruleset-as-Code (RaC)](https://wazuh.com/blog/wazuh-ruleset-as-code-rac/)
- [DaC setup pour GitHub](https://github.com/SamsonIdowu/DaC)
- [DaC setup pour GitLab](https://github.com/0xbbuddha/DaC-Wazuh-Gitlab-setup)
- [GitLab Docs](https://docs.gitlab.com/)
