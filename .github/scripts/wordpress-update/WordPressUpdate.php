<?php

final class WordPressUpdate
{
    private const COMPOSER_TYPES = [
        'plugin' => 'wordpress-plugin',
        'theme' => 'wordpress-theme',
        'core' => 'wordpress-core',
    ];

    private const SLUG_PATTERN = '/^[A-Za-z0-9._-]{1,100}$/D';

    private const VERSION_PATTERN = '/^(\d[0-9A-Za-z.+-]{0,30})?$/D';

    private const ANNOTATION_BUDGET = 3900;

    private const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;

    public static function resolve(array $lock, string $type, string $slug): array
    {
        $composerType = self::COMPOSER_TYPES[$type] ?? null;

        foreach ($lock['packages'] ?? [] as $package) {
            if (($package['type'] ?? null) !== $composerType) {
                continue;
            }

            $name = (string) $package['name'];
            // Premium mirrors are lowercase packages installed into a case-sensitive folder named by installer-name.
            $matches = $type === 'core'
                || strcasecmp(substr($name, strpos($name, '/') + 1), $slug) === 0
                || strcasecmp((string) ($package['extra']['installer-name'] ?? ''), $slug) === 0;

            if ($matches) {
                return ['status' => 'ok', 'package' => $name, 'installed' => self::normalize((string) $package['version'])];
            }
        }

        return ['status' => 'skipped', 'reason' => "{$slug} n'est pas géré par Composer dans ce repo : mise à jour manuelle."];
    }

    public static function pick(array $versions, string $installed, string $patchedIn): array
    {
        if ($patchedIn !== '' && version_compare($installed, $patchedIn, '>=')) {
            return ['status' => 'skipped', 'reason' => "Déjà en {$installed} dans le repo (corrigé en {$patchedIn}) : correctif pas encore déployé ?"];
        }

        $stable = self::stable($versions);
        $target = $stable === [] ? null : end($stable);

        if ($patchedIn === '') {
            if ($target === null || version_compare($target, $installed, '<=')) {
                return ['status' => 'skipped', 'reason' => "Déjà à jour ({$installed})."];
            }

            return ['status' => 'ok', 'target' => $target, 'major_jump' => self::major($target) !== self::major($installed)];
        }

        if ($target === null || version_compare($target, $patchedIn, '<')) {
            $latest = $target ?? 'aucune';

            return ['status' => 'failed', 'reason' => "Aucune version publiée ne corrige la faille (dernière : {$latest}, corrigée en {$patchedIn})."];
        }

        return ['status' => 'ok', 'target' => $target, 'major_jump' => self::major($target) !== self::major($installed)];
    }

    /** Smallest published fix that keeps the installed major.minor, or null: only such a jump is merged without review. */
    public static function pickFix(array $versions, string $installed, string $patchedIn): ?string
    {
        if ($patchedIn === '') {
            return null;
        }

        foreach (self::stable($versions) as $version) {
            if (version_compare($version, $patchedIn, '>=')) {
                $keepsMinor = self::minor($version) === self::minor(self::normalize($installed));

                return $keepsMinor && version_compare($version, self::normalize($installed), '>') ? $version : null;
            }
        }

        return null;
    }

    /** @return list<string> ascending */
    private static function stable(array $versions): array
    {
        $stable = array_values(array_filter(
            array_map(self::normalize(...), $versions),
            fn (string $version): bool => preg_match('/^\d+(\.\d+)*$/D', $version) === 1,
        ));
        usort($stable, 'version_compare');

        return $stable;
    }

    private static function minor(string $version): string
    {
        $parts = explode('.', $version);

        return $parts[0].'.'.($parts[1] ?? '0');
    }

    public static function cleanTitle(string $title): string
    {
        return mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $title)), 0, 120);
    }

    private static function normalize(string $version): string
    {
        return ltrim(trim($version), 'vV');
    }

    private static function major(string $version): string
    {
        return explode('.', $version)[0];
    }

    /** Advisories of the input fixed by $target; the input comes from outside, so invalid fields are dropped. */
    public static function advisories(string $json, string $target): array
    {
        $items = json_decode($json, true);

        if (! is_array($items)) {
            return [];
        }

        $rank = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $fixed = [];

        foreach (array_slice($items, 0, 50) as $item) {
            $patchedIn = is_array($item) ? (string) ($item['patched_in'] ?? '') : '';

            if (preg_match('/^\d[0-9A-Za-z.+-]{0,30}$/D', $patchedIn) !== 1 || version_compare($patchedIn, $target, '>')) {
                continue;
            }

            $cve = (string) ($item['cve'] ?? '');
            $url = (string) ($item['url'] ?? '');
            $severity = (string) ($item['severity'] ?? '');

            $fixed[] = [
                // Pipes would break the Markdown table of the pull request.
                'title' => str_replace('|', '/', self::cleanTitle((string) ($item['title'] ?? ''))),
                'cve' => preg_match('/^CVE-\d{4}-\d{1,7}$/D', $cve) === 1 ? $cve : '',
                'severity' => isset($rank[$severity]) ? $severity : '',
                'patched_in' => $patchedIn,
                'url' => preg_match('#^https://[A-Za-z0-9./?=_%:\#&-]{1,250}$#D', $url) === 1 ? $url : '',
            ];
        }

        usort($fixed, fn (array $a, array $b): int => ($rank[$b['severity']] ?? 0) <=> ($rank[$a['severity']] ?? 0));

        return $fixed;
    }

    public static function commitMessage(array $context): string
    {
        if (($context['advisories'] ?? []) !== []) {
            $lines = array_map(function (array $advisory): string {
                $label = trim("{$advisory['severity']} {$advisory['cve']}");

                return $label !== '' ? "- {$label}: {$advisory['title']}" : "- {$advisory['title']}";
            }, $context['advisories']);

            return self::subject($context)."\n\nSecurity fixes:\n".implode("\n", $lines)."\n";
        }

        if (($context['cve'] ?? '') === '') {
            return self::subject($context)."\n";
        }

        $fix = "Security fix for {$context['cve']}".($context['severity'] !== '' ? " ({$context['severity']})" : '').'.';
        $advisory = $context['advisory_url'] !== '' ? "\nAdvisory: {$context['advisory_url']}" : '';

        return self::subject($context)."\n\n{$fix}{$advisory}\n";
    }

    public static function result(string $status, string $reason, string $prUrl, array $packages, string $autoMerge, string $autoMergeReason): string
    {
        return json_encode([
            'status' => $status,
            'reason' => $reason,
            'pr_url' => $prUrl,
            'packages' => array_values($packages),
            'auto_merge' => $autoMerge,
            'auto_merge_reason' => $autoMergeReason,
        ], self::JSON_FLAGS);
    }

    public static function annotation(?string $resultJson): string
    {
        $message = $resultJson !== null && trim($resultJson) !== ''
            ? trim($resultJson)
            : self::result('failed', "Le workflow s'est arrêté avant de produire un résultat : voir les logs.", '', [], 'not_requested', '');
        $data = json_decode($message, true);

        if (is_array($data) && is_array($data['packages'] ?? null)) {
            $message = self::fit($data);
        }

        return '::notice title=kryzawatch-update::'.self::escape($message);
    }

    // Workflow command data must escape these three, or the annotation is cut or dropped.
    private static function escape(string $message): string
    {
        return strtr($message, ['%' => '%25', "\r" => '%0D', "\n" => '%0A']);
    }

    /** The runner cuts annotation messages at 4096 characters, which would leave Kryzawatch an undecodable JSON. */
    private static function fit(array $data): string
    {
        $cap = fn (mixed $reason): string => mb_substr(is_string($reason) ? $reason : '', 0, 200);
        $data['reason'] = $cap($data['reason'] ?? '');
        $data['auto_merge_reason'] = $cap($data['auto_merge_reason'] ?? '');
        $packages = [];

        foreach (array_values($data['packages']) as $package) {
            if (is_array($package)) {
                unset($package['title'], $package['package']);
                $package['reason'] = $cap($package['reason'] ?? '');
                $packages[] = $package;
            }
        }

        $total = count($packages);
        $data['packages'] = $packages;
        $fits = fn (array $data): bool => strlen(self::escape(json_encode($data, self::JSON_FLAGS))) <= self::ANNOTATION_BUDGET;

        if ($fits($data)) {
            return json_encode($data, self::JSON_FLAGS);
        }

        $defaults = ['reason' => '', 'major_jump' => false, 'from' => ''];
        $data['packages'] = array_map(fn (array $package): array => array_filter(
            $package,
            fn (mixed $value, string|int $key): bool => ! array_key_exists($key, $defaults) || $value !== $defaults[$key],
            ARRAY_FILTER_USE_BOTH,
        ), $data['packages']);

        if ($fits($data)) {
            return json_encode($data, self::JSON_FLAGS);
        }

        $data['packages'] = array_values(array_filter($data['packages'], fn (array $package): bool => ($package['status'] ?? null) === 'updated'));
        $data['omitted'] = $total - count($data['packages']);

        if ($fits($data)) {
            return json_encode($data, self::JSON_FLAGS);
        }

        $data['packages'] = array_map(function (array $package): array {
            unset($package['from']);

            return $package;
        }, $data['packages']);

        while ($data['packages'] !== [] && ! $fits($data)) {
            array_pop($data['packages']);
            $data['omitted']++;
        }

        if ($data['packages'] !== []) {
            return json_encode($data, self::JSON_FLAGS);
        }

        return json_encode([
            'status' => $data['status'] ?? 'failed',
            'reason' => 'Résultat tronqué : voir la PR.',
            'pr_url' => $data['pr_url'] ?? '',
            'packages' => [],
            'omitted' => $total,
            'auto_merge' => $data['auto_merge'] ?? 'not_requested',
            'auto_merge_reason' => $data['auto_merge_reason'],
        ], self::JSON_FLAGS);
    }

    /** The list comes from a dispatch anyone with Actions write can send: every field is checked before use. */
    public static function packages(string $json): array
    {
        $items = json_decode($json, true);

        if (! is_array($items) || ! array_is_list($items) || $items === [] || count($items) > 50) {
            return ['status' => 'invalid', 'reason' => 'packages doit être une liste JSON de 1 à 50 paquets.'];
        }

        $packages = [];

        foreach ($items as $index => $item) {
            $fields = is_array($item) ? $item + ['patched_in' => ''] : [];

            foreach (['type', 'slug', 'title', 'patched_in'] as $key) {
                if (! is_string($fields[$key] ?? null)) {
                    return ['status' => 'invalid', 'reason' => "Paquet n°{$index} invalide."];
                }
            }

            $type = $fields['type'];
            $slug = $fields['slug'];
            $title = self::cleanTitle($fields['title']);
            $patchedIn = $fields['patched_in'];

            if (! isset(self::COMPOSER_TYPES[$type]) || preg_match(self::SLUG_PATTERN, $slug) !== 1 || $title === '' || preg_match(self::VERSION_PATTERN, $patchedIn) !== 1) {
                return ['status' => 'invalid', 'reason' => "Paquet n°{$index} invalide."];
            }

            $packages[] = ['type' => $type, 'slug' => $slug, 'title' => $title, 'patched_in' => $patchedIn];
        }

        return ['status' => 'ok', 'packages' => $packages];
    }

    /** @param array $jobs the `jobs` map of the caller's build.yml: every production deployment must run the smoke test. */
    public static function smokeTestEnabled(array $jobs): bool
    {
        $production = array_filter($jobs, fn (mixed $job): bool => is_array($job) && ($job['with']['environment'] ?? null) === 'production');

        foreach ($production as $job) {
            $smoke = $job['with']['smoke_test'] ?? null;

            if (($smoke !== true && $smoke !== 'true') || ! is_string($job['with']['site_url'] ?? null) || trim($job['with']['site_url']) === '') {
                return false;
            }
        }

        return $production !== [];
    }

    public static function withinBusinessHours(DateTimeImmutable $now): bool
    {
        $local = $now->setTimezone(new DateTimeZone('America/Toronto'));
        $hour = (int) $local->format('G');

        return (int) $local->format('N') <= 5 && $hour >= 8 && $hour < 18;
    }

    public static function prTitleMany(array $packages): string
    {
        $updated = array_values(array_filter($packages, fn (array $package): bool => $package['status'] === 'updated'));

        if (count($updated) === 1) {
            return ($updated[0]['major_jump'] ? '[major] ' : '').self::subject($updated[0]);
        }

        $major = array_filter($updated, fn (array $package): bool => $package['major_jump']) !== [];

        return ($major ? '[major] ' : '').'chore(deps): WordPress updates ('.count($updated).' packages)';
    }

    public static function prBodyMany(array $packages, array $advisories, string $itemId, bool $autoMergeRequested): string
    {
        $status = fn (array $package): string => match ($package['status']) {
            'updated' => $package['major_jump'] ? 'mis à jour **[major]**' : 'mis à jour',
            'skipped' => 'ignoré : '.$package['reason'],
            default => 'échec : '.$package['reason'],
        };
        $cell = fn (string $value): string => str_replace(['|', "\n"], ['/', ' '], $value);

        $lines = ['## Mises à jour WordPress', '', '| Paquet | De | Vers | Statut |', '|---|---|---|---|'];

        foreach ($packages as $package) {
            $lines[] = '| '.$cell($package['title']).' | '.($package['from'] ?: '—').' | '.($package['to'] ?: '—').' | '.$cell($status($package)).' |';
        }

        $lines[] = '';

        if ($advisories !== []) {
            $lines[] = '### Failles corrigées ('.count($advisories).')';
            $lines[] = '';
            $lines[] = '| Sévérité | CVE | Faille | Corrigée en | Avis |';
            $lines[] = '|---|---|---|---|---|';

            foreach ($advisories as $advisory) {
                $link = $advisory['url'] !== '' ? "[Avis]({$advisory['url']})" : '—';
                $lines[] = '| '.($advisory['severity'] ?: '—').' | '.($advisory['cve'] ?: '—')." | {$advisory['title']} | {$advisory['patched_in']} | {$link} |";
            }

            $lines[] = '';
        }

        foreach ($packages as $package) {
            $changelog = $package['status'] === 'updated' ? self::changelogUrl((string) ($package['package'] ?? ''), $package['slug']) : null;

            if ($changelog !== null) {
                $lines[] = '- Changelog '.$cell($package['title']).' : '.$changelog;
            }
        }

        $lines[] = '';

        if ($autoMergeRequested) {
            $lines[] = '> Merge automatique demandé (faille critique) : le résultat est indiqué dans Kryzawatch.';
            $lines[] = '';
        }

        $lines[] = '**Merger cette PR déploie en production.**';
        $lines[] = '';
        $lines[] = "Ouverte par Kryzawatch (item #{$itemId}).";

        return implode("\n", $lines)."\n";
    }

    private static function subject(array $context): string
    {
        return 'chore(deps): upgrade '.self::cleanTitle($context['title'])." from {$context['from']} to {$context['to']}";
    }

    private static function changelogUrl(string $package, string $slug): ?string
    {
        return match (true) {
            str_starts_with($package, 'wp-plugin/'), str_starts_with($package, 'wpackagist-plugin/') => "https://wordpress.org/plugins/{$slug}/#developers",
            str_starts_with($package, 'wp-theme/'), str_starts_with($package, 'wpackagist-theme/') => "https://wordpress.org/themes/{$slug}/",
            $package === 'roots/wordpress-no-content' => 'https://wordpress.org/news/category/releases/',
            default => null,
        };
    }

    /** @param list<string> $files names in wp-content/languages: a locale counts as installed once its core .mo is there. */
    public static function translationLocales(array $files): array
    {
        $locales = [];

        foreach ($files as $file) {
            if (preg_match('/^([a-z]{2,3}_[A-Z]{2}(?:_[a-z0-9]+)?)\.mo$/', (string) $file, $match) === 1) {
                $locales[] = $match[1];
            }
        }

        sort($locales);

        return $locales;
    }

    public static function translationUrl(string $type, string $slug, string $version): ?string
    {
        if (! isset(self::COMPOSER_TYPES[$type]) || preg_match(self::SLUG_PATTERN, $slug) !== 1 || preg_match('/^[0-9][0-9A-Za-z.-]{0,30}$/D', $version) !== 1) {
            return null;
        }

        return $type === 'core'
            ? 'https://api.wordpress.org/translations/core/1.0/?version='.$version
            : "https://api.wordpress.org/translations/{$type}s/1.0/?slug={$slug}&version={$version}";
    }

    /** The answer comes from the network: only a wordpress.org zip for an installed locale is kept. */
    public static function translationPacks(array $api, array $locales): array
    {
        $packs = [];

        foreach (is_array($api['translations'] ?? null) ? $api['translations'] : [] as $translation) {
            $locale = is_array($translation) && is_string($translation['language'] ?? null) ? $translation['language'] : '';
            $package = is_array($translation) && is_string($translation['package'] ?? null) ? $translation['package'] : '';

            if (in_array($locale, $locales, true) && preg_match('#^https://downloads\.wordpress\.org/translation/[A-Za-z0-9._/-]+\.zip$#', $package) === 1) {
                $packs[] = ['locale' => $locale, 'package' => $package];
            }
        }

        return $packs;
    }

}
