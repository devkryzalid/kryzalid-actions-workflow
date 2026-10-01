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

$context = [
    'title' => 'WP-Members',
    'slug' => 'wp-members',
    'type' => 'plugin',
    'package' => 'wpackagist-plugin/wp-members',
    'from' => '3.4.8',
    'to' => '4.0.0',
    'major_jump' => true,
    'cve' => 'CVE-2026-12345',
    'severity' => 'critical',
    'advisory_url' => 'https://www.wordfence.com/threat-intel/vulnerabilities/id/abc',
    'run_site_id' => '42',
];

check('commitMessage follows the maintenance convention',
    SecurityUpdate::commitMessage($context),
    "chore(deps): upgrade WP-Members from 3.4.8 to 4.0.0\n\nSecurity fix for CVE-2026-12345 (critical).\nAdvisory: https://www.wordfence.com/threat-intel/vulnerabilities/id/abc\n");
check('commitMessage without CVE nor advisory',
    SecurityUpdate::commitMessage(['cve' => '', 'severity' => '', 'advisory_url' => ''] + $context),
    "chore(deps): upgrade WP-Members from 3.4.8 to 4.0.0\n\nSecurity fix.\n");
check('prTitle flags a major jump',
    SecurityUpdate::prTitle($context),
    '[major] chore(deps): upgrade WP-Members from 3.4.8 to 4.0.0');
check('prTitle without major jump',
    SecurityUpdate::prTitle(['major_jump' => false] + $context),
    'chore(deps): upgrade WP-Members from 3.4.8 to 4.0.0');

$body = SecurityUpdate::prBody($context);
check('prBody warns about the major jump', str_contains($body, 'Saut de version majeure (3 → 4)'), true);
check('prBody links the wordpress.org changelog', str_contains($body, 'https://wordpress.org/plugins/wp-members/#developers'), true);
check('prBody reminds that merging deploys', str_contains($body, 'Merger cette PR déploie en production.'), true);
check('prBody has no changelog link for a premium mirror',
    str_contains(SecurityUpdate::prBody(['package' => 'kryzalid-premium/tooltippro'] + $context), 'Changelog'),
    false);

check('outcome is single-line JSON',
    SecurityUpdate::outcome('pr_opened', '', 'https://github.com/devkryzalid/q2-guiderc/pull/7', '4.0.0', true),
    '{"status":"pr_opened","reason":"","pr_url":"https://github.com/devkryzalid/q2-guiderc/pull/7","target_version":"4.0.0","major_jump":true}');
// json_encode already turns a newline into the two characters \n; the annotation must only escape %.
check('annotation escapes percent and stays on one line',
    SecurityUpdate::annotation(SecurityUpdate::outcome('failed', "100% raté\nligne 2")),
    '::notice title=security-update::{"status":"failed","reason":"100%25 raté\nligne 2","pr_url":"","target_version":"","major_jump":false}');
check('annotation escapes raw newlines of a hand-written outcome',
    SecurityUpdate::annotation("{\"a\":1}\n{\"b\":2}"),
    '::notice title=security-update::{"a":1}%0A{"b":2}');
check('annotation falls back to failed when no outcome was written',
    SecurityUpdate::annotation(null),
    '::notice title=security-update::{"status":"failed","reason":"Le workflow s\'est arrêté avant de produire un résultat : voir les logs.","pr_url":"","target_version":"","major_jump":false}');


// advisories
$advisories = json_encode([
    ['title' => 'Yoast <= 28.5 - XSS', 'cve' => 'CVE-2026-11111', 'severity' => 'high', 'patched_in' => '28.6', 'url' => 'https://www.wordfence.com/a?x=1&y=2'],
    ['title' => "Yoast <= 28.3 | CSRF\n", 'cve' => '', 'severity' => 'critical', 'patched_in' => '28.4', 'url' => ''],
    ['title' => 'Yoast <= 28.9 - future', 'cve' => 'CVE-2026-22222', 'severity' => 'critical', 'patched_in' => '29.0', 'url' => ''],
    ['title' => 'hostile', 'cve' => 'CVE-bad', 'severity' => 'urgent', 'patched_in' => '28.1', 'url' => 'javascript:alert(1)'],
    'not an object',
]);
$fixed = SecurityUpdate::advisories($advisories, '28.6');
check('advisories keeps only fixes shipped by the target version', count($fixed), 3);
check('advisories sorts by severity', $fixed[0]['severity'], 'critical');
check('advisories neutralises table pipes and control characters', $fixed[0]['title'], 'Yoast <= 28.3 / CSRF');
check('advisories drops an invalid CVE, severity and URL', [$fixed[2]['cve'], $fixed[2]['severity'], $fixed[2]['url']], ['', '', '']);
check('advisories keeps a valid URL', $fixed[1]['url'], 'https://www.wordfence.com/a?x=1&y=2');
check('advisories tolerates garbage', SecurityUpdate::advisories('{oops', '28.6'), []);
check('advisories tolerates an empty input', SecurityUpdate::advisories('', '28.6'), []);

$withAdvisories = ['advisories' => $fixed, 'major_jump' => false, 'from' => '28.5', 'to' => '28.6'] + $context;
check('commitMessage lists every fixed advisory',
    SecurityUpdate::commitMessage($withAdvisories),
    "chore(deps): upgrade WP-Members from 28.5 to 28.6\n\nSecurity fixes:\n- critical: Yoast <= 28.3 / CSRF\n- high CVE-2026-11111: Yoast <= 28.5 - XSS\n- hostile\n");
$body = SecurityUpdate::prBody($withAdvisories);
check('prBody announces the number of fixed advisories', str_contains($body, '### Failles corrigées (3)'), true);
check('prBody links an advisory', str_contains($body, '[Avis](https://www.wordfence.com/a?x=1&y=2)'), true);
check('prBody keeps the single flaw row without advisories', str_contains(SecurityUpdate::prBody($context), '| Faille | CVE-2026-12345 (critical) |'), true);

exit($failures > 0 ? 1 : 0);
