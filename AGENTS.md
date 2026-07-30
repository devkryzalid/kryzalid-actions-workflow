# AGENTS.md

This file provides guidance to coding agents (Claude Code, etc.) when working with code in this repository.

## Nature du repo

Bibliothèque centralisée de **reusable GitHub Actions workflows** (`workflow_call`) consommée par les repos clients KRYZALID. Aucun code applicatif ici — uniquement 6 fichiers YAML dans `.github/workflows/`. Les repos clients référencent ces workflows via `uses: KRYZALID/kryzalid-actions-workflow/.github/workflows/<file>.yml@<ref>`.

Conséquence : **toute modification est une modification d'API publique**. Un changement de signature (inputs/secrets), de comportement de build/deploy, ou de path attendu sur le serveur casse potentiellement tous les repos consommateurs. Préférer ajouts rétro-compatibles (nouveaux inputs avec default), ne pas renommer ni supprimer de secret sans audit.

## Workflows disponibles

Tous prennent `inputs.environment` (`staging` | `production`) et le même set de secrets symétriques `*_STAGING` / `*_PROD` (`SSH_PRIVATE_KEY`, `SSH_USER`, `SERVER_HOST`, `PROJECT_PATH`) + `SLACK_WEBHOOK_URL`.

| Workflow | Stack cible | Comportement clé |
|---|---|---|
| `build-wordpress.yml` | WP avec thème Kryzaplate (Webpack/Vite) | SSH → `git reset --hard origin/<branch>` → auto-détection du dossier contenant `package.json` (priorité `wp-content/themes/*`) → `npm ci` + `npm run dev` (staging) ou `npm run build` (prod) |
| `build-wordpress-divi.yml` | WP avec Divi (pas de build front) | SSH → `git reset --hard` uniquement |
| `build-vuejs.yml` | Vue.js + serveur Node PM2 | Node via nvm (input `node_version`, default 16.20.2), `git reset --hard`, `npm ci` systématique, génère `.env.server`, `npm run build`, `pm2 reload <pm2_app_name>` (ou `pm2 start` au premier run). Job `verify` qui fait failer le workflow si PM2 n'est pas online. Inputs paramétrables : `node_version`, `pm2_app_name` (default `kryzahub-server`), `pm2_entrypoint` (default `server/index.js`), `server_port` (default `3000`). |
| `build-eclosion.yml` | Angular (legacy) | Node 16.14.0 par défaut (input `node_version`), build via `node_modules/@angular/cli/bin/ng.js build --configuration production`, copie `.htaccess`/`robots.txt`/`sitemap*.{xml,xsl}` (sitemap uniquement sur `main`). Job `deploy` séparé qui promeut `dist/` en `releases/<timestamp>/` puis swap atomique du symlink `www`. Inclut un job `check-files` qui notifie Slack si `.browserslistrc` ou `.eslintrc.json` manquent. Input `releases_to_keep` (default 5). |
| `build-eclosion-v2.yml` | Angular 21+ | Variante moderne. Node 22.17.1 par défaut, build via `npm run build` (suppose `angular.json: defaultConfiguration: "production"` côté consommateur), `check-files` cherche `eslint.config.{js,cjs,mjs}` + `tsconfig.json`. Nouvel input `lint_before_build` (boolean, default false) qui exécute `npm run lint` sur le serveur avant le build avec fail-fast si le script `lint` est absent. Garde stricte sur la version Node post-`nvm use`/`install`. Groupe de concurrence `deploy-eclosion-v2-*` (évite la collision avec v1 pendant la migration). **Prérequis serveur** : `nvm` installé, Node 22 installable. |
| `build-teedy.yml` | Teedy front (Node via nvm serveur) | `npm run build` (staging) ou `npm run build:prod` (prod), même mécanisme `releases/` + symlink que eclosion. Input `releases_to_keep` (default 5). |
| `build-teedy-backend.yml` | Teedy backend | SSH → `git reset --hard origin/<branch>` (pas de build) |

## Patterns transverses (à respecter pour cohérence)

### Workflow-level
- **`permissions: contents: read`** (minimum nécessaire — ces workflows utilisent SSH, pas le `GITHUB_TOKEN`).
- **`concurrency:` group** par workflow + environment + repository, avec `cancel-in-progress: false` pour ne jamais interrompre un deploy déjà parti.

### Job-level
- **Job `validate-secrets`** en amont : vérifie la présence des secrets selon `environment` et fail-fast. Tout nouveau workflow doit inclure ce job.
- **Sélection ternaire des secrets** : `${{ inputs.environment == 'staging' && secrets.X_STAGING || secrets.X_PROD }}`. Garder ce pattern (pas de `if:` au niveau job pour switcher).
- **Actions tierces SHA-pinned** avec commentaire de version :
  - `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2`
  - `webfactory/ssh-agent@e83874834305fe9a4a2997156cb26c5de65a8555 # v0.10.0`
  - `slackapi/slack-github-action@45a88b9581bfab2566dc881e2cd66d334e621e2c # v3.0.3`

  Pas de `actions/setup-node` : Node est géré par `nvm` sur le serveur cible, pas sur le runner.

### SSH
- **`ssh-keyscan -H "$SERVER_HOST" >> ~/.ssh/known_hosts`** dans un step dédié, **sans** `StrictHostKeyChecking=no` ensuite. Plus de bypass MITM silencieux.
- **Heredoc SSH** : `bash -s -- "$ARG1" "$ARG2" <<'BASH' ... BASH` avec `set -euo pipefail`. Quoter le délimiteur (`'BASH'`) pour empêcher l'expansion locale des `$VAR` — les variables sont passées en arguments positionnels (`$1`, `$2`).
- **Récupération du code** : toujours `git fetch --all --prune` puis `git reset --hard "origin/$BRANCH"`. Jamais `git pull` (non déterministe en présence de modifs locales).

### Déploiement (eclosion, teedy)
Le swap se fait via **`releases/` + symlink atomique** :
1. Le build produit `dist/`.
2. Le job deploy déplace `dist/ → releases/<timestamp>/`.
3. Swap atomique : `ln -sfn releases/<timestamp> www-new && mv -Tf www-new www`.
4. Rotation : conserve les N dernières releases (input `releases_to_keep`).

**Migration legacy → symlink** : si `www` est encore un dossier réel (pas un symlink) au premier run de cette version, le workflow détecte le cas, déplace `www → wwwbkp-legacy-<timestamp>`, puis crée le symlink. Migration unique et automatique. Le rollback consiste à `ln -sfn releases/<previous> www` (atomique).

**Préservation du sitemap.xml** : sur `main` uniquement, lu via `readlink -f www` (suit le symlink) avant le swap.

### Notifications Slack
- **`slackapi/slack-github-action@v3.0.3`** avec `webhook:` + `webhook-type: incoming-webhook` + `errors: true` (plus de `SLACK_WEBHOOK_URL` en env var, et un échec de POST fait failer le step au lieu de passer silencieusement).
- **Un seul job `notify`** par workflow avec `if: always()`, qui calcule le statut via `contains(needs.*.result, 'failure')` et formate via Block Kit dans un `attachments[]`.
- **`attachments[].color` croise statut et environnement** : prod `#1d7e2a` succès / `#a01515` échec (saturé), staging `#3ec55c` succès / `#d97706` échec (plus clair), `#f0ad4e` pour les warnings `check-files`.
- **Step `Préparer les variables du message`** (`id: meta`) qui définit `color`, `icon`, `env_label`, `deploy_date`, `commit_msg`, `stack_name`, `stack_logo`, `sha_short` en outputs groupés (`{ ... } >> "$GITHUB_OUTPUT"` pour éviter SC2129).
- **`attachments[].fallback` obligatoire** : Slack ne génère aucun aperçu de notification (push mobile, notif desktop, liste de channels) à partir du contenu des `blocks`. Sans `fallback` — ou sans `text` de premier niveau — l'aperçu est vide. Format retenu : `<icon> <env_label> — <repo> (<branch>) — <actor>`, en texte brut sans mrkdwn. Ne pas utiliser `text` de premier niveau : il s'afficherait comme une ligne visible en doublon du block header.
- **Échappement du commit message** : `head -1 | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r'` (échappe backslashes et guillemets, retire CR, garde uniquement la première ligne).

### Validation
- **`yamllint .github/workflows/`** ou **`actionlint .github/workflows/*.yml`** avant commit. `actionlint` détecte les variables GHA invalides, les SC* shellcheck, les contextes incorrects.

## Conventions de commit

Override KRYZALID actif (cf. `~/www/KRYZALID/CLAUDE.md`) : **commits en anglais**, **sans `Co-Authored-By Claude`** (hook bloquant), **demander avant commit/push**. L'historique mélange Conventional Commits et style emoji-préfixé (`⚡️ Improve …`, `🐛 Fix …`, `✨ Add …`, `🔥 Remove …`) — suivre le style emoji déjà en place sur ce repo précis pour rester cohérent avec l'historique.

## Branche

`main` est la branche de release. Les repos consommateurs pinnent souvent `@main` (pas de tag de version) — donc tout commit sur `main` est immédiatement actif en prod ailleurs. Tester localement (ou sur un repo client en staging) avant de merger. **À envisager** : tagger un `v1` stable et migrer progressivement les consommateurs vers `@v1` pour découpler la cadence de cette lib de la prod client.
