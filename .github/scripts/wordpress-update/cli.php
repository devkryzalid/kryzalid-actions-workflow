<?php

require __DIR__.'/WordPressUpdate.php';

$command = $argv[1] ?? '';
$args = array_slice($argv, 2);
$json = fn (array $data): string => json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
$readJson = fn (string $path): array => json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
$advisories = fn (): array => WordPressUpdate::advisories((string) getenv('ADVISORIES'), (string) getenv('TO'));
$context = fn (): array => [
    'title' => (string) getenv('TITLE'),
    'from' => (string) getenv('FROM'),
    'to' => (string) getenv('TO'),
    'cve' => '',
    'severity' => '',
    'advisory_url' => '',
    'advisories' => $advisories(),
];

echo match ($command) {
    'packages' => $json(WordPressUpdate::packages($args[0] ?? '')),
    'resolve' => $json(WordPressUpdate::resolve($readJson($args[0]), $args[1], $args[2])),
    'pick' => $json(WordPressUpdate::pick($readJson($args[0])['versions'] ?? [], $args[1], $args[2], $args[3] ?? throw new InvalidArgumentException('pick needs the package type'))),
    'pick-fix' => (string) WordPressUpdate::pickFix($readJson($args[0])['versions'] ?? [], $args[1], $args[2]),
    'smoke' => WordPressUpdate::smokeTestEnabled((array) json_decode(is_file($args[0] ?? '') ? (string) file_get_contents($args[0]) : '', true)) ? 'true' : 'false',
    'hours' => WordPressUpdate::withinBusinessHours(new DateTimeImmutable('now')) ? 'true' : 'false',
    'commit-message' => WordPressUpdate::commitMessage($context()),
    'pr-title' => WordPressUpdate::prTitleMany($readJson($args[0])),
    'pr-body' => WordPressUpdate::prBodyMany($readJson($args[0]), WordPressUpdate::advisories((string) getenv('ADVISORIES'), '999999'), $args[1], $args[2] ?? ''),
    'result' => WordPressUpdate::result($args[0], $args[1] ?? '', $args[2] ?? '', is_file($args[3] ?? '') ? $readJson($args[3]) : [], $args[4] ?? 'not_requested', $args[5] ?? ''),
    'translation-locales' => implode(' ', WordPressUpdate::translationLocales(is_dir($args[0] ?? '') ? scandir($args[0]) : [])),
    'translation-url' => (string) WordPressUpdate::translationUrl($args[0] ?? '', $args[1] ?? '', $args[2] ?? ''),
    'translation-packs' => implode("\n", array_map(fn (array $pack): string => "{$pack['locale']} {$pack['package']}", WordPressUpdate::translationPacks((array) json_decode(is_file($args[0] ?? '') ? (string) file_get_contents($args[0]) : '', true), explode(' ', $args[1] ?? '')))),
    'annotation' => WordPressUpdate::annotation(is_file($args[0] ?? '') ? (string) file_get_contents($args[0]) : null),
    default => throw new InvalidArgumentException("Unknown command: {$command}"),
}, "\n";
