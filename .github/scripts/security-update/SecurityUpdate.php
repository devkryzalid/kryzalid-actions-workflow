<?php

final class SecurityUpdate
{
    private const COMPOSER_TYPES = [
        'plugin' => 'wordpress-plugin',
        'theme' => 'wordpress-theme',
        'core' => 'wordpress-core',
    ];

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
        if (version_compare($installed, $patchedIn, '>=')) {
            return ['status' => 'skipped', 'reason' => "Déjà en {$installed} dans le repo (corrigé en {$patchedIn}) : correctif pas encore déployé ?"];
        }

        $stable = array_values(array_filter(
            array_map(self::normalize(...), $versions),
            fn (string $version): bool => preg_match('/^\d+(\.\d+)*$/', $version) === 1,
        ));
        usort($stable, 'version_compare');
        $target = $stable === [] ? null : end($stable);

        if ($target === null || version_compare($target, $patchedIn, '<')) {
            $latest = $target ?? 'aucune';

            return ['status' => 'failed', 'reason' => "Aucune version publiée ne corrige la faille (dernière : {$latest}, corrigée en {$patchedIn})."];
        }

        return ['status' => 'ok', 'target' => $target, 'major_jump' => self::major($target) !== self::major($installed)];
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

    public static function commitMessage(array $context): string
    {
        $fix = $context['cve'] !== ''
            ? "Security fix for {$context['cve']}".($context['severity'] !== '' ? " ({$context['severity']})" : '').'.'
            : 'Security fix.';
        $advisory = $context['advisory_url'] !== '' ? "\nAdvisory: {$context['advisory_url']}" : '';

        return self::subject($context)."\n\n{$fix}{$advisory}\n";
    }

    public static function prTitle(array $context): string
    {
        return ($context['major_jump'] ? '[major] ' : '').self::subject($context);
    }

    public static function prBody(array $context): string
    {
        $flaw = trim(($context['cve'] !== '' ? $context['cve'] : 'Sans CVE').($context['severity'] !== '' ? " ({$context['severity']})" : ''));
        $lines = [
            '## Correctif de sécurité',
            '',
            '| | |',
            '|---|---|',
            "| Composant | `{$context['slug']}` ({$context['type']}) |",
            "| Version | {$context['from']} → {$context['to']} |",
            "| Faille | {$flaw} |",
        ];

        if ($context['advisory_url'] !== '') {
            $lines[] = "| Avis | {$context['advisory_url']} |";
        }

        $lines[] = '';

        if ($context['major_jump']) {
            $from = explode('.', $context['from'])[0];
            $to = explode('.', $context['to'])[0];
            $lines[] = "> **Saut de version majeure ({$from} → {$to})** : lire le changelog avant de merger.";
            $lines[] = '';
        }

        $changelog = self::changelogUrl($context['package'], $context['slug']);

        if ($changelog !== null) {
            $lines[] = "Changelog : {$changelog}";
            $lines[] = '';
        }

        $lines[] = '**Merger cette PR déploie en production.**';
        $lines[] = '';
        $lines[] = "Ouverte par Kryzawatch (run site #{$context['run_site_id']}).";

        return implode("\n", $lines)."\n";
    }

    public static function outcome(string $status, string $reason = '', string $prUrl = '', string $target = '', bool $majorJump = false): string
    {
        return json_encode([
            'status' => $status,
            'reason' => $reason,
            'pr_url' => $prUrl,
            'target_version' => $target,
            'major_jump' => $majorJump,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    public static function annotation(?string $outcomeJson): string
    {
        $message = $outcomeJson ?? self::outcome('failed', "Le workflow s'est arrêté avant de produire un résultat : voir les logs.");

        // Workflow command data must escape these three, or the annotation is cut or dropped.
        return '::notice title=security-update::'.strtr(trim($message), ['%' => '%25', "\r" => '%0D', "\n" => '%0A']);
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
