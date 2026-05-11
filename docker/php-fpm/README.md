# nvelox + PHP-FPM integration test

A self-contained docker-compose stack that proves nvelox's FastCGI
routing works end-to-end against a real PHP-FPM. Useful for:

- Smoke-testing FastCGI wiring after touching `core/httpproxy/fastcgi.go`
  or the route matcher.
- Validating `split_path_info`, `try_files` fallback, and static-vs-PHP
  resolution against actual Apache/nginx behaviour.
- Reproducing field issues operators report with `fastcgi: pass: ...`
  configs.

## Layout

```
docker/php-fpm/
├── docker-compose.yml      two services, one private network
├── nvelox.conf             :8080 → FastCGI php-fpm:9000
├── www/                    document root mounted on both containers
│   ├── index.php           front-controller
│   ├── info.php            phpinfo()
│   ├── form.php            POST body / headers echo
│   ├── upload.php          multipart $_FILES echo
│   └── style.css           static asset (must be served WITHOUT touching PHP)
└── README.md               (this file)
```

## Run

```bash
cd docker/php-fpm
docker compose up --build
```

First run builds the nvelox image from `../../Dockerfile` (~30s). Subsequent
runs are instant. Use `docker compose up -d` to background.

`docker compose logs nvelox` and `docker compose logs php-fpm` show the
respective stdout/stderr.

## Test

### 1. Front-controller fallback

```bash
curl -s http://localhost:8080/
```

`try_files` doesn't find `/`, falls through to `/index.php`. Expect:

```
OK from PHP 8.3.x
REQUEST_METHOD : GET
REQUEST_URI    : /
SCRIPT_NAME    : /index.php
…
```

### 2. Direct PHP

```bash
curl -s http://localhost:8080/index.php
```

Same body as above — index.php executed by name.

### 3. PATH_INFO (split_path_info)

```bash
curl -s http://localhost:8080/index.php/some/path
```

Expect:

```
SCRIPT_NAME    : /index.php
PATH_INFO      : /some/path
```

`split_path_info: "^(.+\\.php)(/.*)$"` in nvelox.conf splits the URI into
SCRIPT_NAME + PATH_INFO before forwarding to PHP-FPM — same as nginx's
`fastcgi_split_path_info`.

### 4. Static file served directly

```bash
curl -sD - -o /dev/null http://localhost:8080/style.css
```

200 OK with `Content-Type: text/css`. Crucially **no** `X-Served-By`
header (PHP didn't run). nvelox served the file straight from
`/var/www/html` via its `static:` handler.

### 5. POST body forwarded

```bash
curl -s -X POST -d 'name=ada&value=42' http://localhost:8080/form.php
```

Expect a JSON blob with `"post": {"name":"ada","value":"42"}` and
`"headers": {"content-type":"application/x-www-form-urlencoded", …}`.
Proves the request body streamed through nvelox → FastCGI → PHP intact.

### 6. Multipart upload

```bash
echo "hello" > /tmp/payload.txt
curl -s -X POST -F file=@/tmp/payload.txt http://localhost:8080/upload.php
```

Expect a JSON blob with `"files.file.name": "p.txt"` and the file
contents echoed back via `tmp_read`. Proves the whole multipart body
streamed through nvelox into PHP-FPM, which parsed it into `$_FILES`.

### 7. phpinfo (manual inspection)

```bash
curl -s http://localhost:8080/info.php | head -50
```

Look for the `_SERVER` section — every CGI var nvelox set is listed there.
Quick way to debug a misbehaving `params:` block in production.

### 8. Hot reload

```bash
# Edit nvelox.conf (change a header, add a route, etc.), then:
docker compose kill -s HUP nvelox

# Next request reflects the new config; in-flight ones aren't dropped.
curl -sD - -o /dev/null http://localhost:8080/
docker compose logs --tail 20 nvelox | grep RELOAD
```

## Teardown

```bash
docker compose down -v
```

## Troubleshooting

- **502 Bad Gateway**: php-fpm container isn't healthy yet. Wait 1–2s
  after `up`, or check `docker compose logs php-fpm`.
- **No such file or directory** in PHP logs: SCRIPT_FILENAME points at
  a path PHP-FPM can't see. Both containers must mount the same
  document root at the same path (`/var/www/html` by default).
- **404 on a real .php file**: regex didn't match. Check
  `path_regex: "\\.php(/|$)"` in `nvelox.conf`. Note the
  double-backslash inside YAML double-quoted strings.
