<?php

require __DIR__.'/../SecurityUpdate.php';

$failures = 0;

function check(string $name, mixed $actual, mixed $expected): void
{
    global $failures;

    if ($actual === $expected) {
        echo "ok   {$name}\n";

        return;
    }

    $failures++;
    fwrite(STDERR, "FAIL {$name}\n  expected: ".var_export($expected, true)."\n  actual:   ".var_export($actual, true)."\n");
}

$lock = ['packages' => [
    ['name' => 'roots/wordpress-no-content', 'version' => '7.1.1', 'type' => 'wordpress-core'],
    ['name' => 'wpackagist-plugin/wp-members', 'version' => '3.4.8', 'type' => 'wordpress-plugin'],
    ['name' => 'kryzalid-premium/tooltippro', 'version' => 'v2.0.0', 'type' => 'wordpress-plugin', 'extra' => ['installer-name' => 'TooltipPro']],
    ['name' => 'wpackagist-theme/astra', 'version' => '4.1.0', 'type' => 'wordpress-theme'],
    ['name' => 'composer/installers', 'version' => '2.3.0', 'type' => 'composer-plugin'],
]];

// resolve
check('resolve plugin by package name',
    SecurityUpdate::resolve($lock, 'plugin', 'wp-members'),
    ['status' => 'ok', 'package' => 'wpackagist-plugin/wp-members', 'installed' => '3.4.8']);
check('resolve premium plugin by installer-name, version prefix stripped',
    SecurityUpdate::resolve($lock, 'plugin', 'TooltipPro'),
    ['status' => 'ok', 'package' => 'kryzalid-premium/tooltippro', 'installed' => '2.0.0']);
check('resolve theme',
    SecurityUpdate::resolve($lock, 'theme', 'astra')['package'],
    'wpackagist-theme/astra');
check('resolve core ignores slug',
    SecurityUpdate::resolve($lock, 'core', 'wordpress')['package'],
    'roots/wordpress-no-content');
check('resolve does not match a plugin slug against a theme',
    SecurityUpdate::resolve($lock, 'plugin', 'astra')['status'],
    'skipped');
check('resolve skips a component outside Composer (Divi)',
    SecurityUpdate::resolve($lock, 'theme', 'Divi'),
    ['status' => 'skipped', 'reason' => "Divi n'est pas géré par Composer dans ce repo : mise à jour manuelle."]);

// pick
$versions = ['dev-trunk', '4.0.0', '3.5.12', '3.5.8', '3.4.8', '4.1.0-beta1', 'v3.5.9'];
check('pick targets the latest stable even across a major',
    SecurityUpdate::pick($versions, '3.4.8', '3.5.8'),
    ['status' => 'ok', 'target' => '4.0.0', 'major_jump' => true]);
check('pick within the same major',
    SecurityUpdate::pick(['3.5.12', '3.5.8', 'dev-trunk'], '3.4.8', '3.5.8'),
    ['status' => 'ok', 'target' => '3.5.12', 'major_jump' => false]);
check('pick handles 2 and 4 segment versions',
    SecurityUpdate::pick(['7.1', '7.0.6', '2.4.14.1'], '7.0.5', '7.0.6'),
    ['status' => 'ok', 'target' => '7.1', 'major_jump' => false]);
check('pick skips when the repo already carries the fix',
    SecurityUpdate::pick($versions, '3.5.8', '3.5.8'),
    ['status' => 'skipped', 'reason' => 'Déjà en 3.5.8 dans le repo (corrigé en 3.5.8) : correctif pas encore déployé ?']);
check('pick fails when no published version carries the fix',
    SecurityUpdate::pick(['3.5.7', '3.5.6'], '3.4.8', '3.5.8'),
    ['status' => 'failed', 'reason' => 'Aucune version publiée ne corrige la faille (dernière : 3.5.7, corrigée en 3.5.8).']);
check('pick fails on an empty list',
    SecurityUpdate::pick([], '3.4.8', '3.5.8')['status'],
    'failed');

// cleanTitle
check('cleanTitle flattens control characters',
    SecurityUpdate::cleanTitle("WP-Members\n; rm -rf /\t"),
    'WP-Members ; rm -rf /');
check('cleanTitle caps the length',
    mb_strlen(SecurityUpdate::cleanTitle(str_repeat('é', 300))),
    120);

exit($failures > 0 ? 1 : 0);
