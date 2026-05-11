<?php
// Front-controller-style entry. nvelox's try_files falls through to
// /index.php when the requested URI isn't a static file.

header('X-Served-By: nvelox+phpfpm');
header('Content-Type: text/plain');

$path = $_SERVER['PATH_INFO'] ?? $_SERVER['REQUEST_URI'] ?? '/';

echo "OK from PHP " . PHP_VERSION . "\n";
echo "REQUEST_METHOD : " . $_SERVER['REQUEST_METHOD'] . "\n";
echo "REQUEST_URI    : " . ($_SERVER['REQUEST_URI'] ?? '') . "\n";
echo "SCRIPT_NAME    : " . $_SERVER['SCRIPT_NAME'] . "\n";
echo "SCRIPT_FILENAME: " . $_SERVER['SCRIPT_FILENAME'] . "\n";
echo "PATH_INFO      : " . ($_SERVER['PATH_INFO'] ?? '(none)') . "\n";
echo "QUERY_STRING   : " . ($_SERVER['QUERY_STRING'] ?? '') . "\n";
echo "REMOTE_ADDR    : " . ($_SERVER['REMOTE_ADDR'] ?? '') . "\n";
echo "HTTP_HOST      : " . ($_SERVER['HTTP_HOST'] ?? '') . "\n";
echo "X-Forwarded-For: " . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '(none)') . "\n";
echo "X-Real-IP      : " . ($_SERVER['HTTP_X_REAL_IP'] ?? '(none)') . "\n";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    echo "\n--- POST body ---\n";
    echo file_get_contents('php://input') . "\n";
}
