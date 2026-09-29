<?php

require __DIR__.'/SecurityUpdate.php';

$command = $argv[1] ?? '';
$args = array_slice($argv, 2);
$json = fn (array $data): string => json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
$readJson = fn (string $path): array => json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
$context = fn (): array => [
    'title' => (string) getenv('TITLE'),
    'slug' => (string) getenv('SLUG'),
    'type' => (string) getenv('TYPE'),
    'package' => (string) getenv('PACKAGE'),
    'from' => (string) getenv('FROM'),
    'to' => (string) getenv('TO'),
    'major_jump' => getenv('MAJOR_JUMP') === 'true',
    'cve' => (string) getenv('CVE'),
    'severity' => (string) getenv('SEVERITY'),
    'advisory_url' => (string) getenv('ADVISORY_URL'),
    'run_site_id' => (string) getenv('RUN_SITE_ID'),
];

echo match ($command) {
    'resolve' => $json(SecurityUpdate::resolve($readJson($args[0]), $args[1], $args[2])),
    'pick' => $json(SecurityUpdate::pick($readJson($args[0])['versions'] ?? [], $args[1], $args[2])),
    'commit-message' => SecurityUpdate::commitMessage($context()),
    'pr-title' => SecurityUpdate::prTitle($context()),
    'pr-body' => SecurityUpdate::prBody($context()),
    'outcome' => SecurityUpdate::outcome($args[0], $args[1] ?? '', $args[2] ?? '', $args[3] ?? '', ($args[4] ?? '') === 'true'),
    'annotation' => SecurityUpdate::annotation(is_file($args[0] ?? '') ? (string) file_get_contents($args[0]) : null),
    default => throw new InvalidArgumentException("Unknown command: {$command}"),
}, "\n";
