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
| `build-eclosion.yml` | Angular | Node 16.14.0 par défaut (input `node_version`), build via `node_modules/@angular/cli/bin/ng.js build --configuration production`, copie `.htaccess`/`robots.txt`/`sitemap*.{xml,xsl}` (sitemap uniquement sur `main`). Job `deploy` séparé qui promeut `dist/` en `releases/<timestamp>/` puis swap atomique du symlink `www`. Inclut un job `check-files` qui notifie Slack si `.browserslistrc` ou `.eslintrc.json` manquent. Input `releases_to_keep` (default 5). |
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
  - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`
  - `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0`
  - `webfactory/ssh-agent@a6f90b1f127823b31d4d4a8d96047790581349bd # v0.9.1`
  - `slackapi/slack-github-action@b0fa283ad8fea605de13dc3f449259339835fc52 # v2.1.0`

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
- **`slackapi/slack-github-action@v2.1.0`** avec `webhook:` + `webhook-type: incoming-webhook` (nouvelle API v2, plus de `SLACK_WEBHOOK_URL` en env var).
- **Un seul job `notify`** par workflow avec `if: always()`, qui calcule le statut via `contains(needs.*.result, 'failure')` et formate via Block Kit avec `attachments[].color` (#36a64f succès, #dc3545 échec, #f0ad4e warning).
- **Step `Préparer les variables du message`** qui définit `color`, `icon`, `status_text`, `env_icon`, `deploy_date`, `commit_msg` en outputs groupés (`{ ... } >> "$GITHUB_OUTPUT"` pour éviter SC2129).
- **Échappement du commit message** : `head -1 | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r'` (échappe backslashes et guillemets, retire CR, garde uniquement la première ligne).

### Validation
- **`yamllint .github/workflows/`** ou **`actionlint .github/workflows/*.yml`** avant commit. `actionlint` détecte les variables GHA invalides, les SC* shellcheck, les contextes incorrects.

## Conventions de commit

Override KRYZALID actif (cf. `~/www/KRYZALID/CLAUDE.md`) : **commits en anglais**, **sans `Co-Authored-By Claude`** (hook bloquant), **demander avant commit/push**. L'historique mélange Conventional Commits et style emoji-préfixé (`⚡️ Improve …`, `🐛 Fix …`, `✨ Add …`, `🔥 Remove …`) — suivre le style emoji déjà en place sur ce repo précis pour rester cohérent avec l'historique.

## Branche

`main` est la branche de release. Les repos consommateurs pinnent souvent `@main` (pas de tag de version) — donc tout commit sur `main` est immédiatement actif en prod ailleurs. Tester localement (ou sur un repo client en staging) avant de merger. **À envisager** : tagger un `v1` stable et migrer progressivement les consommateurs vers `@v1` pour découpler la cadence de cette lib de la prod client.
