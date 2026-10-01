<?php

final class WordPressUpdate
{
    private const COMPOSER_TYPES = [
        'plugin' => 'wordpress-plugin',
        'theme' => 'wordpress-theme',
        'core' => 'wordpress-core',
    ];

    private const SLUG_PATTERN = '/^[A-Za-z0-9._-]{1,100}$/';

    private const VERSION_PATTERN = '/^(\d[0-9A-Za-z.+-]{0,30})?$/';

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
                return self::minor($version) === self::minor(self::normalize($installed)) ? $version : null;
            }
        }

        return null;
    }

    /** @return list<string> ascending */
    private static function stable(array $versions): array
    {
        $stable = array_values(array_filter(
            array_map(self::normalize(...), $versions),
            fn (string $version): bool => preg_match('/^\d+(\.\d+)*$/', $version) === 1,
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

            if (preg_match('/^\d[0-9A-Za-z.+-]{0,30}$/', $patchedIn) !== 1 || version_compare($patchedIn, $target, '>')) {
                continue;
            }

            $cve = (string) ($item['cve'] ?? '');
            $url = (string) ($item['url'] ?? '');
            $severity = (string) ($item['severity'] ?? '');

            $fixed[] = [
                // Pipes would break the Markdown table of the pull request.
                'title' => str_replace('|', '/', self::cleanTitle((string) ($item['title'] ?? ''))),
                'cve' => preg_match('/^CVE-\d{4}-\d{1,7}$/', $cve) === 1 ? $cve : '',
                'severity' => isset($rank[$severity]) ? $severity : '',
                'patched_in' => $patchedIn,
                'url' => preg_match('#^https://[A-Za-z0-9./?=_%:\#&-]{1,250}$#', $url) === 1 ? $url : '',
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
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    public static function annotation(?string $resultJson): string
    {
        $message = $resultJson ?? self::result('failed', "Le workflow s'est arrêté avant de produire un résultat : voir les logs.", '', [], 'not_requested', '');

        // Workflow command data must escape these three, or the annotation is cut or dropped.
        return '::notice title=kryzawatch-update::'.strtr(trim($message), ['%' => '%25', "\r" => '%0D', "\n" => '%0A']);
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
            $type = is_array($item) ? (string) ($item['type'] ?? '') : '';
            $slug = is_array($item) ? (string) ($item['slug'] ?? '') : '';
            $title = is_array($item) ? self::cleanTitle((string) ($item['title'] ?? '')) : '';
            $patchedIn = is_array($item) ? (string) ($item['patched_in'] ?? '') : '';

            if (! isset(self::COMPOSER_TYPES[$type]) || preg_match(self::SLUG_PATTERN, $slug) !== 1 || $title === '' || preg_match(self::VERSION_PATTERN, $patchedIn) !== 1) {
                return ['status' => 'invalid', 'reason' => "Paquet n°{$index} invalide."];
            }

            $packages[] = ['type' => $type, 'slug' => $slug, 'title' => $title, 'patched_in' => $patchedIn];
        }

        return ['status' => 'ok', 'packages' => $packages];
    }

    public static function smokeTestEnabled(string $buildYml): bool
    {
        return preg_match('/^\s*smoke_test:\s*true\s*$/m', $buildYml) === 1;
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
            str_starts_with($package, 'wpackagist-plugin/') => "https://wordpress.org/plugins/{$slug}/#developers",
            str_starts_with($package, 'wpackagist-theme/') => "https://wordpress.org/themes/{$slug}/",
            $package === 'roots/wordpress-no-content' => 'https://wordpress.org/news/category/releases/',
            default => null,
        };
    }
}
