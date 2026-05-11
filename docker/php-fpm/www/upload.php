<?php
header('Content-Type: application/json');
echo json_encode([
    'method' => $_SERVER['REQUEST_METHOD'],
    'content_type' => $_SERVER['HTTP_CONTENT_TYPE'] ?? '',
    'files' => array_map(fn($f) => [
        'name' => $f['name'], 'size' => $f['size'], 'tmp_read' => @file_get_contents($f['tmp_name']),
    ], $_FILES),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
