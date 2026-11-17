<?php
// Echo back what we got. Useful to verify nvelox correctly streams
// POST bodies (Content-Length / Content-Type / multipart) to FastCGI.

header('Content-Type: application/json');

$out = [
    'method'  => $_SERVER['REQUEST_METHOD'],
    'query'   => $_GET,
    'post'    => $_POST,
    'body'    => file_get_contents('php://input'),
    'headers' => [],
];
foreach ($_SERVER as $k => $v) {
    if (str_starts_with($k, 'HTTP_')) {
        $out['headers'][strtolower(substr($k, 5))] = $v;
    }
}
echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
