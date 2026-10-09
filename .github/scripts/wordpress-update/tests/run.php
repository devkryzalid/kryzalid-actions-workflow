<?php

require __DIR__.'/../WordPressUpdate.php';

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
    WordPressUpdate::resolve($lock, 'plugin', 'wp-members'),
    ['status' => 'ok', 'package' => 'wpackagist-plugin/wp-members', 'installed' => '3.4.8']);
check('resolve premium plugin by installer-name, version prefix stripped',
    WordPressUpdate::resolve($lock, 'plugin', 'TooltipPro'),
    ['status' => 'ok', 'package' => 'kryzalid-premium/tooltippro', 'installed' => '2.0.0']);
check('resolve theme',
    WordPressUpdate::resolve($lock, 'theme', 'astra')['package'],
    'wpackagist-theme/astra');
check('resolve core ignores slug',
    WordPressUpdate::resolve($lock, 'core', 'wordpress')['package'],
    'roots/wordpress-no-content');
check('resolve does not match a plugin slug against a theme',
    WordPressUpdate::resolve($lock, 'plugin', 'astra')['status'],
    'skipped');
check('resolve skips a component outside Composer (Divi)',
    WordPressUpdate::resolve($lock, 'theme', 'Divi'),
    ['status' => 'skipped', 'reason' => "Divi n'est pas géré par Composer dans ce repo : mise à jour manuelle."]);

// pick
$versions = ['dev-trunk', '4.0.0', '3.5.12', '3.5.8', '3.4.8', '4.1.0-beta1', 'v3.5.9'];
check('pick targets the latest stable even across a major',
    WordPressUpdate::pick($versions, '3.4.8', '3.5.8', 'plugin'),
    ['status' => 'ok', 'target' => '4.0.0', 'major_jump' => true]);
check('pick within the same major',
    WordPressUpdate::pick(['3.5.12', '3.5.8', 'dev-trunk'], '3.4.8', '3.5.8', 'plugin'),
    ['status' => 'ok', 'target' => '3.5.12', 'major_jump' => false]);
check('pick handles 2 and 4 segment versions',
    WordPressUpdate::pick(['7.1', '7.0.6', '2.4.14.1'], '7.0.5', '7.0.6', 'plugin'),
    ['status' => 'ok', 'target' => '7.1', 'major_jump' => false]);
check('pick skips when the repo already carries the fix',
    WordPressUpdate::pick($versions, '3.5.8', '3.5.8', 'plugin'),
    ['status' => 'skipped', 'reason' => 'Déjà en 3.5.8 dans le repo (corrigé en 3.5.8) : correctif pas encore déployé ?']);
check('pick fails when no published version carries the fix',
    WordPressUpdate::pick(['3.5.7', '3.5.6'], '3.4.8', '3.5.8', 'plugin'),
    ['status' => 'failed', 'reason' => 'Aucune version publiée ne corrige la faille (dernière : 3.5.7, corrigée en 3.5.8).']);
check('pick fails on an empty list',
    WordPressUpdate::pick([], '3.4.8', '3.5.8', 'plugin')['status'],
    'failed');

// cleanTitle
check('cleanTitle flattens control characters',
    WordPressUpdate::cleanTitle("WP-Members\n; rm -rf /\t"),
    'WP-Members ; rm -rf /');
check('cleanTitle caps the length',
    mb_strlen(WordPressUpdate::cleanTitle(str_repeat('é', 300))),
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
    WordPressUpdate::commitMessage($context),
    "chore(deps): upgrade WP-Members from 3.4.8 to 4.0.0\n\nSecurity fix for CVE-2026-12345 (critical).\nAdvisory: https://www.wordfence.com/threat-intel/vulnerabilities/id/abc\n");


// advisories
$advisories = json_encode([
    ['title' => 'Yoast <= 28.5 - XSS', 'cve' => 'CVE-2026-11111', 'severity' => 'high', 'patched_in' => '28.6', 'url' => 'https://www.wordfence.com/a?x=1&y=2'],
    ['title' => "Yoast <= 28.3 | CSRF\n", 'cve' => '', 'severity' => 'critical', 'patched_in' => '28.4', 'url' => ''],
    ['title' => 'Yoast <= 28.9 - future', 'cve' => 'CVE-2026-22222', 'severity' => 'critical', 'patched_in' => '29.0', 'url' => ''],
    ['title' => 'hostile', 'cve' => 'CVE-bad', 'severity' => 'urgent', 'patched_in' => '28.1', 'url' => 'javascript:alert(1)'],
    'not an object',
]);
$fixed = WordPressUpdate::advisories($advisories, '28.6');
check('advisories keeps only fixes shipped by the target version', count($fixed), 3);
check('advisories sorts by severity', $fixed[0]['severity'], 'critical');
check('advisories neutralises table pipes and control characters', $fixed[0]['title'], 'Yoast <= 28.3 / CSRF');
check('advisories drops an invalid CVE, severity and URL', [$fixed[2]['cve'], $fixed[2]['severity'], $fixed[2]['url']], ['', '', '']);
check('advisories keeps a valid URL', $fixed[1]['url'], 'https://www.wordfence.com/a?x=1&y=2');
check('advisories tolerates garbage', WordPressUpdate::advisories('{oops', '28.6'), []);
check('advisories tolerates an empty input', WordPressUpdate::advisories('', '28.6'), []);

$withAdvisories = ['advisories' => $fixed, 'major_jump' => false, 'from' => '28.5', 'to' => '28.6'] + $context;
check('commitMessage lists every fixed advisory',
    WordPressUpdate::commitMessage($withAdvisories),
    "chore(deps): upgrade WP-Members from 28.5 to 28.6\n\nSecurity fixes:\n- critical: Yoast <= 28.3 / CSRF\n- high CVE-2026-11111: Yoast <= 28.5 - XSS\n- hostile\n");

// result and annotation
$pkgs = [['type' => 'plugin', 'slug' => 'wp-members', 'from' => '3.4.8', 'to' => '3.5.12', 'status' => 'updated', 'reason' => '', 'major_jump' => false]];
check('result is single-line JSON with the package list',
    WordPressUpdate::result('pr_opened', '', 'https://github.com/devkryzalid/q2-guiderc/pull/7', $pkgs, 'not_requested', ''),
    '{"status":"pr_opened","reason":"","pr_url":"https://github.com/devkryzalid/q2-guiderc/pull/7","packages":[{"type":"plugin","slug":"wp-members","from":"3.4.8","to":"3.5.12","status":"updated","reason":"","major_jump":false}],"auto_merge":"not_requested","auto_merge_reason":""}');
check('annotation is the result in hex, which neither the raw nor the base64 form of a masked secret line can match',
    WordPressUpdate::annotation(WordPressUpdate::result('failed', "100% raté\nligne 2", '', [], 'not_requested', '')),
    '::notice title=kryzawatch-update::'.bin2hex('{"status":"failed","reason":"100% raté\nligne 2","pr_url":"","packages":[],"auto_merge":"not_requested","auto_merge_reason":""}'));
$trailingBrace = WordPressUpdate::result('pr_opened', '', 'https://github.com/devkryzalid/csl/pull/65', [['type' => 'plugin', 'slug' => 'cookiebot', 'from' => '4.7.3', 'to' => '4.7.5', 'status' => 'updated', 'reason' => '', 'major_jump' => false]], 'not_requested', '');
check('a result whose base64 ends in fQ== (masked for a secret line holding only }) survives in hex',
    [str_ends_with(base64_encode($trailingBrace), 'fQ=='), str_contains(WordPressUpdate::annotation($trailingBrace), 'fQ=='), str_ends_with(WordPressUpdate::annotation($trailingBrace), '7d')],
    [true, false, true]);
check('annotation keeps a hand-written result on one line',
    WordPressUpdate::annotation("{\"a\":1}\n{\"b\":2}"),
    '::notice title=kryzawatch-update::'.bin2hex("{\"a\":1}\n{\"b\":2}"));
check('annotation falls back to failed when no result was written',
    WordPressUpdate::annotation(null),
    '::notice title=kryzawatch-update::'.bin2hex('{"status":"failed","reason":"Le workflow s\'est arrêté avant de produire un résultat : voir les logs.","pr_url":"","packages":[],"auto_merge":"not_requested","auto_merge_reason":""}'));

check('annotation treats an empty result like a missing one',
    WordPressUpdate::annotation(" \n"), WordPressUpdate::annotation(null));
check('annotation substitutes invalid UTF-8 instead of throwing',
    str_contains(hex2bin(substr(WordPressUpdate::annotation(WordPressUpdate::result('failed', "bad \xC3", '', [], 'not_requested', '')), strlen('::notice title=kryzawatch-update::'))), "\"reason\":\"bad \u{FFFD}\""), true);
check('annotation drops title and package from the packages',
    WordPressUpdate::annotation(WordPressUpdate::result('pr_opened', '', 'https://github.com/o/r/pull/1', [['type' => 'plugin', 'slug' => 'a', 'title' => 'A', 'package' => 'wpackagist-plugin/a', 'from' => '1.0', 'to' => '1.1', 'status' => 'updated', 'reason' => '', 'major_jump' => false]], 'not_requested', '')),
    '::notice title=kryzawatch-update::'.bin2hex('{"status":"pr_opened","reason":"","pr_url":"https://github.com/o/r/pull/1","packages":[{"type":"plugin","slug":"a","from":"1.0","to":"1.1","status":"updated","reason":"","major_jump":false}],"auto_merge":"not_requested","auto_merge_reason":""}'));

// The runner cuts annotation messages at 4096 characters.
$decodeAnnotation = fn (string $line): ?array => json_decode((string) hex2bin(substr($line, strlen('::notice title=kryzawatch-update::'))), true);
$bulk = [];
for ($i = 0; $i < 47; $i++) {
    $bulk[] = ['type' => 'plugin', 'slug' => str_pad("plugin-{$i}-", 25, 'x'), 'title' => str_repeat('T', 120), 'package' => 'wpackagist-plugin/'.str_pad("plugin-{$i}-", 25, 'x'), 'from' => '10.12.3', 'to' => '10.12.4', 'status' => 'updated', 'reason' => '', 'major_jump' => $i === 0];
}
for ($i = 0; $i < 3; $i++) {
    $bulk[] = ['type' => 'theme', 'slug' => "broken-{$i}", 'title' => 'Broken', 'package' => '', 'from' => '1.0', 'to' => '', 'status' => 'failed', 'reason' => str_repeat("composer require a échoué 100%\n", 40), 'major_jump' => false];
}
$line = WordPressUpdate::annotation(WordPressUpdate::result('pr_opened', str_repeat('r', 3000), 'https://github.com/devkryzalid/q2-guiderc/pull/1234', $bulk, 'refused', str_repeat('m', 3000)));
$decoded = $decodeAnnotation($line);
$keptUpdated = array_values(array_filter($decoded['packages'] ?? [], fn (array $package): bool => $package['status'] === 'updated'));
check('annotation of 50 packages stays under the runner limit', strlen($line) <= 4096, true);
check('annotation of 50 packages is valid JSON', is_array($decoded), true);
check('annotation keeps the leading updated packages in order with slug and to',
    array_map(fn (array $package): array => [$package['slug'], $package['to']], $keptUpdated),
    array_map(fn (array $package): array => [$package['slug'], $package['to']], array_slice($bulk, 0, count($keptUpdated))));
check('annotation counts every dropped package in omitted', count($decoded['packages'] ?? []) + ($decoded['omitted'] ?? 0), 50);
check('annotation keeps most updated packages (15 here)', count($keptUpdated), 15);
check('annotation keeps the top-level fields', [$decoded['status'], $decoded['pr_url'], $decoded['auto_merge'], mb_strlen($decoded['reason']), mb_strlen($decoded['auto_merge_reason'])],
    ['pr_opened', 'https://github.com/devkryzalid/q2-guiderc/pull/1234', 'refused', 200, 200]);
check('annotation caps package reasons at 200 characters',
    mb_strlen($decodeAnnotation(WordPressUpdate::annotation(WordPressUpdate::result('failed', '', '', [$bulk[47]], 'not_requested', '')))['packages'][0]['reason']), 200);

$absurd = array_map(fn (int $i): array => ['type' => 'plugin', 'slug' => str_pad((string) $i, 100, 'z'), 'from' => str_repeat('9', 64), 'to' => str_repeat('9', 64), 'status' => 'updated', 'reason' => '', 'major_jump' => true], range(1, 50));
$line = WordPressUpdate::annotation(WordPressUpdate::result('pr_opened', '%%%%', 'https://github.com/o/r/pull/1', $absurd, 'not_requested', ''));
$decoded = $decodeAnnotation($line);
check('annotation of absurd input stays under the runner limit', strlen($line) <= 4096, true);
check('annotation of absurd input is valid JSON with every package accounted for', is_array($decoded) ? count($decoded['packages']) + $decoded['omitted'] : null, 50);
$line = WordPressUpdate::annotation(WordPressUpdate::result('pr_opened', '', 'https://github.com/o/r/pull/'.str_repeat('1', 3600), $absurd, 'merged', ''));
check('annotation of a last resort stays under the runner limit', strlen($line) <= 4096, true);
check('annotation falls back to a truncated result as a last resort',
    array_intersect_key($decodeAnnotation($line) ?? [], array_flip(['reason', 'packages', 'omitted', 'auto_merge'])),
    ['reason' => 'Résultat tronqué : voir la PR.', 'packages' => [], 'omitted' => 50, 'auto_merge' => 'merged']);

// packages
check('packages accepts a valid list',
    WordPressUpdate::packages('[{"type":"plugin","slug":"wp-members","title":"WP-Members","patched_in":"3.5.8"},{"type":"core","slug":"wordpress","title":"WordPress","patched_in":""}]'),
    ['status' => 'ok', 'packages' => [
        ['type' => 'plugin', 'slug' => 'wp-members', 'title' => 'WP-Members', 'patched_in' => '3.5.8'],
        ['type' => 'core', 'slug' => 'wordpress', 'title' => 'WordPress', 'patched_in' => ''],
    ]]);
check('packages rejects invalid JSON', WordPressUpdate::packages('{')['status'], 'invalid');
check('packages rejects an empty list', WordPressUpdate::packages('[]')['status'], 'invalid');
check('packages rejects more than 50 entries',
    WordPressUpdate::packages(json_encode(array_fill(0, 51, ['type' => 'plugin', 'slug' => 'a', 'title' => 'A', 'patched_in' => ''])))['status'],
    'invalid');
check('packages rejects an unknown type',
    WordPressUpdate::packages('[{"type":"mu-plugin","slug":"a","title":"A","patched_in":""}]')['status'],
    'invalid');
check('packages rejects a slug with shell characters',
    WordPressUpdate::packages('[{"type":"plugin","slug":"a;rm","title":"A","patched_in":""}]')['status'],
    'invalid');
check('packages rejects a malformed patched_in',
    WordPressUpdate::packages('[{"type":"plugin","slug":"a","title":"A","patched_in":"1.0 && x"}]')['status'],
    'invalid');
check('packages flattens control characters in titles',
    WordPressUpdate::packages("[{\"type\":\"plugin\",\"slug\":\"a\",\"title\":\"A\\nB\",\"patched_in\":\"\"}]")['packages'][0]['title'],
    'A B');
check('packages rejects an empty title',
    WordPressUpdate::packages('[{"type":"plugin","slug":"a","title":" ","patched_in":""}]')['status'],
    'invalid');

// pick in routine mode (no patched_in)
check('pick without patched_in targets the latest stable above the installed one',
    WordPressUpdate::pick(['3.5.12', '3.4.8', 'dev-trunk'], '3.4.8', '', 'plugin'),
    ['status' => 'ok', 'target' => '3.5.12', 'major_jump' => false]);
check('pick without patched_in skips an up-to-date package',
    WordPressUpdate::pick(['3.5.12', '3.4.8'], '3.5.12', '', 'plugin'),
    ['status' => 'skipped', 'reason' => 'Déjà à jour (3.5.12).']);

// Same major rule as Kryzawatch's UpdateCatalog::isMajor(): x.y for the core, the first segment otherwise.
check('pick flags a core x.y change as major',
    WordPressUpdate::pick(['7.2.0', '7.1.3'], '7.1.3', '', 'core'),
    ['status' => 'ok', 'target' => '7.2.0', 'major_jump' => true]);
check('pick keeps a core maintenance release non major',
    WordPressUpdate::pick(['7.1.4', '7.1.3'], '7.1.3', '', 'core'),
    ['status' => 'ok', 'target' => '7.1.4', 'major_jump' => false]);
check('pick keeps a plugin minor release non major',
    WordPressUpdate::pick(['28.6', '28.5'], '28.5', '', 'plugin'),
    ['status' => 'ok', 'target' => '28.6', 'major_jump' => false]);
check('pick flags a plugin first-segment change as major',
    WordPressUpdate::pick(['5.0', '4.9'], '4.9', '', 'plugin'),
    ['status' => 'ok', 'target' => '5.0', 'major_jump' => true]);

// pickFix
check('pickFix takes the smallest fixed version of the same minor',
    WordPressUpdate::pickFix(['3.4.12', '3.4.9', '3.4.10', '3.5.0', 'v3.4.11'], '3.4.8', '3.4.9'),
    '3.4.9');
check('pickFix refuses when the smallest fix changes the minor',
    WordPressUpdate::pickFix(['3.5.0', '3.5.1'], '3.4.8', '3.5.0'),
    null);
check('pickFix refuses when no published version carries the fix',
    WordPressUpdate::pickFix(['3.4.8'], '3.4.8', '3.4.9'),
    null);
check('pickFix ignores pre-releases',
    WordPressUpdate::pickFix(['3.4.9-beta1', '3.4.10'], '3.4.8', '3.4.9'),
    '3.4.10');
check('pickFix refuses an empty patched_in',
    WordPressUpdate::pickFix(['3.4.9'], '3.4.8', ''),
    null);

// smokeTestEnabled reads the decoded `jobs` map of the caller's build.yml
$prod = fn (array $with): array => ['uses' => 'KRYZALID/kryzalid-actions-workflow/.github/workflows/build-wordpress.yml@main', 'with' => $with];
check('smoke test on with a production job running it against a URL',
    WordPressUpdate::smokeTestEnabled([
        'staging' => $prod(['environment' => 'staging']),
        'production' => $prod(['environment' => 'production', 'smoke_test' => true, 'site_url' => 'https://x.ca']),
    ]), true);
check('smoke test on with the string true',
    WordPressUpdate::smokeTestEnabled(['production' => $prod(['environment' => 'production', 'smoke_test' => 'true', 'site_url' => 'https://x.ca'])]), true);
check('smoke test off when only staging runs it',
    WordPressUpdate::smokeTestEnabled([
        'staging' => $prod(['environment' => 'staging', 'smoke_test' => true, 'site_url' => 'https://staging.x.ca']),
        'production' => $prod(['environment' => 'production']),
    ]), false);
check('smoke test off without site_url',
    WordPressUpdate::smokeTestEnabled(['production' => $prod(['environment' => 'production', 'smoke_test' => true, 'site_url' => ' '])]), false);
check('smoke test off when one of two production jobs skips it',
    WordPressUpdate::smokeTestEnabled([
        'production-a' => $prod(['environment' => 'production', 'smoke_test' => true, 'site_url' => 'https://a.ca']),
        'production-b' => $prod(['environment' => 'production', 'smoke_test' => false, 'site_url' => 'https://b.ca']),
    ]), false);
check('smoke test off without a production job',
    WordPressUpdate::smokeTestEnabled(['staging' => $prod(['environment' => 'staging', 'smoke_test' => true, 'site_url' => 'https://x.ca'])]), false);
$both = "\${{ github.ref_name == 'dev' && 'staging' || 'production' }}";
$bothUrl = "\${{ github.ref_name == 'dev' && 'https://s.x.ca' || 'https://x.ca' }}";
check('smoke test on with one job deploying both environments from an expression',
    WordPressUpdate::smokeTestEnabled(['wordpress-build' => $prod(['environment' => $both, 'smoke_test' => true, 'site_url' => $bothUrl])]), true);
check('smoke test off on an expression job without smoke_test',
    WordPressUpdate::smokeTestEnabled(['wordpress-build' => $prod(['environment' => $both, 'smoke_test' => false, 'site_url' => $bothUrl])]), false);
check('smoke test off on an expression job without site_url',
    WordPressUpdate::smokeTestEnabled(['wordpress-build' => $prod(['environment' => $both, 'smoke_test' => true])]), false);
check('an expression that only mentions staging is not a production job',
    WordPressUpdate::smokeTestEnabled(['wordpress-build' => $prod(['environment' => "\${{ github.ref_name == 'dev' && 'staging' || 'qa' }}", 'smoke_test' => true, 'site_url' => 'https://x.ca'])]), false);
check('smoke test off on an empty or malformed jobs map',
    [WordPressUpdate::smokeTestEnabled([]), WordPressUpdate::smokeTestEnabled(['x' => 'y'])], [false, false]);

// withinBusinessHours
$tz = new DateTimeZone('America/Toronto');
check('business hours on a weekday morning',
    WordPressUpdate::withinBusinessHours(new DateTimeImmutable('2026-09-30 08:00', $tz)), true);
check('business hours end at 18h',
    WordPressUpdate::withinBusinessHours(new DateTimeImmutable('2026-09-30 18:00', $tz)), false);
check('business hours closed on saturday',
    WordPressUpdate::withinBusinessHours(new DateTimeImmutable('2026-10-03 10:00', $tz)), false);
check('business hours read in Toronto time from a UTC clock',
    WordPressUpdate::withinBusinessHours(new DateTimeImmutable('2026-09-30 12:30', new DateTimeZone('UTC'))), true);
check('business hours closed at 23h UTC which is 19h in Toronto',
    WordPressUpdate::withinBusinessHours(new DateTimeImmutable('2026-09-30 23:00', new DateTimeZone('UTC'))), false);

// commitMessage for a routine update
check('commitMessage without advisories nor CVE is the subject alone',
    WordPressUpdate::commitMessage(['title' => 'Yoast SEO', 'from' => '28.5', 'to' => '28.6', 'cve' => '', 'severity' => '', 'advisory_url' => '', 'advisories' => []]),
    "chore(deps): upgrade Yoast SEO from 28.5 to 28.6\n");

// prTitleMany and prBodyMany
$many = [
    ['type' => 'plugin', 'slug' => 'wordpress-seo', 'title' => 'Yoast SEO', 'package' => 'wpackagist-plugin/wordpress-seo', 'from' => '27.5', 'to' => '28.6', 'status' => 'updated', 'reason' => '', 'major_jump' => true],
    ['type' => 'plugin', 'slug' => 'redirection', 'title' => 'Redirection', 'package' => 'wpackagist-plugin/redirection', 'from' => '5.5.2', 'to' => '5.6.0', 'status' => 'updated', 'reason' => '', 'major_jump' => false],
    ['type' => 'plugin', 'slug' => 'gravityforms', 'title' => 'Gravity Forms', 'package' => 'gravity/gravityforms', 'from' => '2.9.1', 'to' => '', 'status' => 'failed', 'reason' => 'composer require a échoué', 'major_jump' => false],
];
check('prTitleMany names the count and flags a major',
    WordPressUpdate::prTitleMany($many),
    '[major] chore(deps): WordPress updates (2 packages)');
check('prTitleMany with a single update is its commit subject',
    WordPressUpdate::prTitleMany([$many[1]]),
    'chore(deps): upgrade Redirection from 5.5.2 to 5.6.0');
$bodyMany = WordPressUpdate::prBodyMany($many, [], '42', '');
check('prBodyMany lists every package with its status', str_contains($bodyMany, '| Gravity Forms | 2.9.1 | — | échec : composer require a échoué |'), true);
check('prBodyMany neutralises pipes in reasons', str_contains(WordPressUpdate::prBodyMany([['reason' => 'a | b', 'status' => 'failed', 'to' => ''] + $many[2]], [], '42', ''), 'a / b'), true);
check('prBodyMany reminds that merging deploys', str_contains($bodyMany, 'Merger cette PR déploie en production.'), true);
check('prBodyMany names the Kryzawatch item', str_contains($bodyMany, 'Ouverte par Kryzawatch (item #42).'), true);
check('prBodyMany announces an automatic merge', str_contains(WordPressUpdate::prBodyMany([$many[1]], [], '42', 'true'), 'Merge automatique demandé'), true);
check('prBodyMany names the critical-fix mode', str_contains(WordPressUpdate::prBodyMany([$many[1]], [], '42', 'true'), 'Merge automatique demandé (faille critique)'), true);
check('prBodyMany names the routine mode', str_contains(WordPressUpdate::prBodyMany([$many[1]], [], '42', 'routine'), 'Merge automatique demandé (mise à jour courante)'), true);
check('prBodyMany says nothing of a merge when none is asked', str_contains(WordPressUpdate::prBodyMany([$many[1]], [], '42', ''), 'Merge automatique'), false);
$bodyAdvisories = WordPressUpdate::prBodyMany([$many[1]], $fixed, '42', '');
check('prBodyMany announces the number of fixed advisories', str_contains($bodyAdvisories, '### Failles corrigées (3)'), true);
check('prBodyMany links an advisory', str_contains($bodyAdvisories, '[Avis](https://www.wordfence.com/a?x=1&y=2)'), true);
check('prBodyMany links the wordpress.org changelog', str_contains($bodyMany, 'https://wordpress.org/plugins/redirection/#developers'), true);
check('prBodyMany links the wordpress.org changelog of a WP Packages plugin', str_contains(WordPressUpdate::prBodyMany([['package' => 'wp-plugin/redirection'] + $many[1], $many[0]], [], '42', ''), 'https://wordpress.org/plugins/redirection/#developers'), true);

// untrusted input edge cases
check('packages rejects a slug with a trailing newline',
    WordPressUpdate::packages("[{\"type\":\"plugin\",\"slug\":\"a\\n\",\"title\":\"A\",\"patched_in\":\"\"}]")['status'],
    'invalid');
check('packages rejects a patched_in with a trailing newline',
    WordPressUpdate::packages("[{\"type\":\"plugin\",\"slug\":\"a\",\"title\":\"A\",\"patched_in\":\"1.0\\n\"}]")['status'],
    'invalid');
check('packages rejects a non-string field',
    WordPressUpdate::packages('[{"type":["x"],"slug":"a","title":"A","patched_in":""}]')['status'],
    'invalid');
check('packages accepts an absent patched_in',
    WordPressUpdate::packages('[{"type":"plugin","slug":"a","title":"A"}]')['packages'][0]['patched_in'],
    '');
check('pickFix refuses a fix older than the installed version',
    WordPressUpdate::pickFix(['3.4.5', '3.4.8', '3.4.9'], '3.4.8', '3.4.5'),
    null);

// translations
check('translationLocales keeps the core language files only',
    WordPressUpdate::translationLocales(['fr_CA.mo', 'fr_FR.mo', 'admin-fr_CA.mo', 'continents-cities-fr_FR.mo', 'fr_CA.po', 'de_DE_formal.mo', 'pt_BR.l10n.php', 'plugins', 'en.mo']),
    ['de_DE_formal', 'fr_CA', 'fr_FR']);
check('translationUrl for a plugin',
    WordPressUpdate::translationUrl('plugin', 'better-wp-security', '10.0.5'),
    'https://api.wordpress.org/translations/plugins/1.0/?slug=better-wp-security&version=10.0.5');
check('translationUrl for a theme',
    WordPressUpdate::translationUrl('theme', 'astra', '4.1.0'),
    'https://api.wordpress.org/translations/themes/1.0/?slug=astra&version=4.1.0');
check('translationUrl for the core ignores the slug',
    WordPressUpdate::translationUrl('core', 'wordpress', '7.1.2'),
    'https://api.wordpress.org/translations/core/1.0/?version=7.1.2');
check('translationUrl refuses a slug or a version outside the allowed characters',
    [WordPressUpdate::translationUrl('plugin', '../x', '1.0'), WordPressUpdate::translationUrl('plugin', 'x', '1.0&slug=y'), WordPressUpdate::translationUrl('plugin', 'x', "1.0\n")],
    [null, null, null]);
$api = ['translations' => [
    ['language' => 'fr_FR', 'package' => 'https://downloads.wordpress.org/translation/plugin/x/1.0/fr_FR.zip'],
    ['language' => 'de_DE', 'package' => 'https://downloads.wordpress.org/translation/plugin/x/1.0/de_DE.zip'],
    ['language' => 'fr_CA', 'package' => 'https://evil.example/fr_CA.zip'],
]];
check('translationPacks keeps the installed locales with a wordpress.org package',
    WordPressUpdate::translationPacks($api, ['fr_CA', 'fr_FR']),
    [['locale' => 'fr_FR', 'package' => 'https://downloads.wordpress.org/translation/plugin/x/1.0/fr_FR.zip']]);
check('translationPacks survives a malformed answer',
    [WordPressUpdate::translationPacks([], ['fr_FR']), WordPressUpdate::translationPacks(['translations' => [['language' => ['x']], 'y']], ['fr_FR'])],
    [[], []]);

// The dispatch inputs are validated in bash: the regex is read from the workflow so this test follows it. /D matches bash's end of string.
preg_match('/\[\[ "\$AUTO_MERGE" =~ (\S+) \]\]/', (string) file_get_contents(__DIR__.'/../../../workflows/update-wordpress.yml'), $autoMergeRule);
$autoMergeAccepts = fn (string $value): int => preg_match('/'.($autoMergeRule[1] ?? 'rule-not-found').'/D', $value);
check('auto_merge accepts empty, true and routine', array_map($autoMergeAccepts, ['', 'true', 'routine']), [1, 1, 1]);
check('auto_merge refuses any other value', array_map($autoMergeAccepts, ['false', 'TRUE', 'routine ', "true\n", 'routinex', 'truer']), [0, 0, 0, 0, 0, 0]);

exit($failures > 0 ? 1 : 0);
