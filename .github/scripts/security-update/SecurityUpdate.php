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
}
