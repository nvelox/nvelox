# Configuration reference

Every setting nvelox reads from its configuration file, under the key it is written as. `[]` stands for each item of a list, `<name>` for each key of a map. The page is made from nvelox's source, so it names every setting of the version it comes with; nvelox.example.yaml shows them in a configuration.

## The top level

- **`version`** (text): The version of the configuration format: "2". Any other value is refused.
- **`server`** (section): Settings of the process: the user it runs as, its event loops, how it stops, the limits of HTTP/3.
- **`logging`** (section): Where the access log and the error log go, and how much the error log says.
- **`metrics`** (section): The Prometheus metrics endpoint.
- **`admin`** (section): The admin API: statistics, the backends and their servers, and the denylist, changed at run time.
- **`tracing`** (section): Not built yet: a configuration that sets any of its keys is refused at load.
- **`include`** (text): More configuration files whose listeners and backends are added to this file's, as a file pattern such as "conf.d/*.yaml". The pattern is read from this file's directory, and every file it matches must lie under that directory: a pattern with ".." is refused. An included file holds listeners, backends and version only (the same version as this file's); any other key in it is refused.
- **`listeners`** (list of sections): The ports nvelox listens on, and what it does with what comes in.
- **`backends`** (list of sections): The servers nvelox passes traffic to, in named groups that listeners and routes refer to.

## `server`

- **`user`** (text): The user nvelox runs as once it has bound its ports, when it is started as root. Empty: it keeps the user it was started as. Started as another user, nvelox cannot switch, and says so at start.
- **`group`** (text): The group nvelox runs as once it has bound its ports, when it is started as root. Empty: the group of user.
- **`pid_file`** (text): Where nvelox writes its process ID, once every port is bound and before it switches to user, so that the file can lie in a directory only root writes to; a clean stop removes it. Empty (the default): no file. Read at start: a reload does not move it.
- **`workers`** (number): How many event loops nvelox runs, and so how many CPU cores it uses for traffic: 1 to 1024. 0 (the default): one for each CPU core the process may use. Read at start: a reload does not change it.
- **`gateway_id`** (text): A name for this nvelox, written on every line of the HTTP access log as gw=<name>, so that a request can be traced to the gateway that first received it. Empty (the default): the machine's host name.
- **`shutdown_timeout`** (text): How long a stop (SIGINT or SIGTERM) lets the HTTP requests in flight finish before what is left is closed: a duration greater than 0, such as 30s. Default 10s. A reload applies it.
- **`http3`** (section): The limits of HTTP/3 connections, for every listener that serves HTTP/3.

## `server.http3`

- **`max_header_size`** (text): The largest header section a request may have, counted as HTTP/3 counts it (names, values and 32 bytes a field); a larger one is answered 431. A connection may have 100 requests open and so hold 100 heads on their way: 6.4 MiB with the default, 100 MiB with 1MB. 1KB to 1MB, default 64KB.
- **`max_send_buffer`** (text): The most one connection holds of its answers that the client has not acknowledged: what it holds follows what its path carries, up to this, so it is also the most a download moves per round trip. 256KB to 1GB, default 16MB.
- **`max_stream_receive_window`** (text): How far the window for one request's body grows. A window starts at 1 MiB and doubles while the backend takes an upload as fast as the path brings it, so this is the most one upload moves per round trip, and the most nvelox holds of it when the backend stops taking. 1MB (nothing grows) to 1GB, default 6MB.
- **`max_connection_receive_window`** (text): How far the window for all the request bodies of one connection together grows, as max_stream_receive_window does for one: the most a connection's uploads move per round trip. 1MB (nothing grows) to 1GB, default 15MB.
- **`max_send_memory`** (text): The most all connections together hold to send; past it a connection takes 16 KiB at a time. 1MB to 1024GB. Default: an eighth of the memory nvelox may use (the machine's, or its control group's limit), 64 MiB at the least.
- **`max_receive_memory`** (text): The most all connections together are granted to receive beyond their first windows; past it no window grows. 1MB to 1024GB. Default: an eighth of the memory nvelox may use, 64 MiB at the least.
- **`socket_buffer`** (text): What nvelox asks the kernel for as the receive and as the send buffer of each UDP socket of an HTTP/3 listener: there is one socket per event loop. A burst of a fast client's datagrams waits in the receive buffer until its loop reads it, and what does not fit is dropped, which slows an upload down. The kernel grants up to net.core.rmem_max and wmem_max, and the whole of it to a process started with CAP_NET_ADMIN; a listener whose sockets got less says so in a startup warning. 64KB to 64MB, default 4MB.
- **`handshakes_per_source`** (number): How many QUIC handshakes one client address (an IPv4 address, or an IPv6 /64) may have running at once on each event loop; behind a trusted relay, the address the relay names. The first packets of its further clients are dropped, and counted in nvelox_h3_handshakes_refused_total{reason="per_source"}, until one of its handshakes completes or is given up (after 10 s); a client sends them again. Clients behind one address, a company's NAT say, share it. 0 (no limit) to 4096 (all of a loop's handshakes), default 32.

## `logging`

- **`level`** (text): How much the error log says: debug, info, warning or error. Default info.
- **`access_log`** (text): The file the access log is written to. Empty (the default): standard output. nvelox opens the file again on SIGUSR1 or SIGHUP, after log rotation has moved it away.
- **`error_log`** (text): The file the error log is written to. Empty (the default): standard error. nvelox opens the file again on SIGUSR1 or SIGHUP.
- **`access`** (true or false): Turns the access log on or off for every listener; on when not set. A listener's own access_log wins over it.

## `metrics`

- **`enabled`** (true or false): Turns the metrics endpoint on.
- **`bind`** (text): The address the metrics endpoint listens on. Default 127.0.0.1:9090: the loopback interface only.
- **`path`** (text): The path the metrics are served at. Default /metrics.

## `admin`

- **`enabled`** (true or false): Turns the admin API on. It needs api_key: without one nvelox does not start.
- **`bind`** (text): The address the admin API listens on. Default 127.0.0.1:9091: the loopback interface only.
- **`api_key`** (text): The key every request to the admin API sends in its X-API-Key header. Required when the admin API is on.

## `tracing`

- **`enabled`** (true or false): Not built yet: a configuration that sets it is refused at load.
- **`endpoint`** (text): Not built yet: a configuration that sets it is refused at load.
- **`service`** (text): Not built yet: a configuration that sets it is refused at load.

## `listeners[]`

- **`name`** (text): The listener's name, in log lines and in metrics. Required, and one to a listener.
- **`bind`** (text): The address and port to listen on, such as ":80", "10.0.0.1:443" or "[::]:443", or a range of ports, such as ":17000-17100", served from one socket each. Required.
- **`protocol`** (text): What the listener speaks: tcp (the default) and udp relay connections and datagrams to a backend as they are; http and https serve HTTP, https behind TLS.
- **`zero_copy`** (true or false): Not built yet: a listener that sets it to true is refused at load.
- **`backend`** (text): The backend to pass traffic to, by its name. A tcp or udp listener passes every connection or session to it, and needs one. An http or https listener with routes passes it the requests no route takes; without routes, every request.
- **`default_backend`** (text): The former name of backend. A listener that uses it loads, with a warning that names the new key; one that sets both is refused.
- **`server_names`** (list of text): The host names this listener answers for when several http or https listeners share one bind address: matched against the TLS server name and the Host header, an exact name first, then one with a wildcard in its leftmost label ("*.example.com"). A listener alone on its address answers for every name. Refused on tcp and udp.
- **`default_server`** (true or false): Makes this listener the one that answers a request whose name no listener on its bind address lists. At most one to a bind address. Refused on tcp and udp.
- **`rate_limit`** (section): A limit for the whole listener: new connections a second on tcp, new sessions on udp, requests on http and https.
- **`timeouts`** (section): How long the listener waits for its clients, and how long it gives a backend to accept a connection. Refused on a udp listener: a udp session ends after 60 seconds without a datagram from its client, or 10 seconds without a reply from its backend.
- **`tls`** (section): The certificate an https listener, or a tcp listener that ends TLS, presents, and how it treats client certificates.
- **`sni_routes`** (list of sections): Not built yet: a listener that sets it is refused at load.
- **`ip_allowlist`** (list of text): Addresses and ranges ("10.0.0.0/8") allowed in: any other client is refused. Empty: every client. On http and https it is the client of each request (behind trusted_proxies, the client they name); on tcp and udp, of each connection or session (behind a relay of accept_proxy_from, the client its header names).
- **`ip_denylist`** (list of text): Addresses and ranges refused, with the same client as ip_allowlist.
- **`max_body_size`** (text): The largest request body an http or https listener takes, such as "10MB"; a larger one is answered 413. Empty: no limit. Refused on tcp and udp listeners.
- **`ip_rate_limit`** (section): A limit of requests a second for each client address, on http and https listeners: past it a request is answered 429. Refused on tcp and udp listeners.
- **`acl`** (list of sections): Rules that allow or refuse requests by their client, method, path and headers, checked in order: the first that matches decides, and a request no rule matches is allowed. On tcp and udp a rule matches the client address only.
- **`trusted_proxies`** (list of text): Addresses and ranges of the proxies in front of an http or https listener whose X-Forwarded-For, X-Real-IP and X-Forwarded-Proto are believed: for a request from one of them, the client those headers name is the client for the access log, ip_allowlist, ip_denylist, ip_rate_limit and acl, and nvelox adds to the headers. From any other address the headers are replaced, so a client cannot claim another address. Empty: nobody is trusted. List only the proxies themselves: behind a Kubernetes Service with externalTrafficPolicy: Cluster, every packet comes from a node's address, so a range of node addresses would trust every client. Refused on tcp and udp listeners, which learn the client from a relay's header (accept_proxy_from).
- **`accept_proxy_from`** (list of text): Addresses and ranges of the relays (another nvelox, HAProxy) whose PROXY protocol version 2 header names the client: the client it names is the client for every address-based control. A listed relay must send the header, on every connection and in every datagram: a connection without a valid one is closed, a datagram dropped (the relay's own traffic, such as health checks, sends a LOCAL header). Anyone else is the client itself, header or not. Empty (the default): nobody. A datagram's source address can be forged, so a udp listener should also set accept_proxy_key_file or accept_proxy_interfaces; one that trusts by address alone starts with a warning. Listeners on one bind address set the same.
- **`accept_proxy_key_file`** (text): A file of keys, one to a line (32 characters at least; "#" begins a comment), that a relay's PROXY header must be signed with: a header without a valid signature closes its connection or drops its datagram. A sending nvelox signs with send_proxy_key_file. Every key in the file is accepted, so a key is rotated without a gap: add the new one here, sign with it on the relays, then remove the old one.
- **`accept_proxy_replay_window`** (text): What a signed header must carry. A header signed with a counter (signature version 2) is bound to the relay socket that sent it and refused when its counter was taken before or is older than that socket's last 64: a copy of it does not pass. "when_present" (the default) also takes a header signed without one (version 1, from a relay not updated yet); "required" takes only headers with a counter, once every relay sends them. Needs accept_proxy_key_file.
- **`accept_proxy_interfaces`** (list of text): On a udp listener (Linux): network interfaces, such as a second network card, a VLAN or a tunnel only the relays reach, on which a relay's header counts. A datagram from a listed relay that arrived on another interface is an ordinary client's. For relays that cannot sign their headers. The interfaces and their addresses are read at start.
- **`http3`** (true or false): Serves HTTP/3 too, on an https listener: over UDP, on the listener's port, with its certificate.
- **`routes`** (list of sections): Rules that pick, for each request of an http or https listener, the backend, the files or the FastCGI server that answers it, checked in order: the first route that matches takes the request. Refused on tcp and udp listeners.
- **`headers`** (section): Request and response headers added, set or removed for every request of an http or https listener. Refused on tcp and udp listeners.
- **`compression`** (section): Compresses responses with gzip, for the clients that accept it, on http and https listeners. Refused on tcp and udp listeners.
- **`error_pages`** (map of number to text): Pages of your own for error answers, by status code, such as 404: "/etc/nvelox/404.html": a file read at start and at each reload (one that cannot be read is logged, and the built-in page is used). Refused on tcp and udp listeners.
- **`root`** (text): Not built for a listener: a listener that sets it is refused at load. A route's static.root serves files.
- **`buffering`** (section): The size of the buffer response bodies are copied through. Refused on tcp and udp listeners.
- **`cache`** (section): A cache of responses in memory, on http and https listeners. Refused on tcp and udp listeners.
- **`grpc`** (true or false): Not built yet: a listener that sets it to true is refused at load. gRPC is proxied to backends with backend_tls without it.
- **`throttle`** (section): Not built yet: a listener that sets it is refused at load.
- **`request_id`** (section): A request ID (X-Request-ID) for every request: kept from the client when it is trusted, else made, passed to the backend, returned to the client and written in the access log. Refused on tcp and udp listeners.
- **`access_log`** (true or false): Turns this listener's access-log lines on or off, whatever logging.access says.

## `listeners[].rate_limit`

- **`connections_per_second`** (number): What the listener takes a second over time: new connections (tcp), new sessions (udp) or requests (http, https). Past it a connection is closed, a session's datagrams dropped, a request answered 429. 0 (the default): no limit.
- **`burst`** (number): How many the listener takes at once before the rate counts. Default 1.

## `listeners[].timeouts`

- **`connect`** (text): How long opening a connection to a server may take, such as "5s": a backend's own, else its listener's, else 10s. When it fails a request is answered 502, a tcp client's connection closed. "0": no limit.
- **`read_header`** (text): On an http or https listener: how long a client may take to send a request's head. Default 10s. The listeners on one bind address share one value, the largest they set. "0": no limit. Refused on a tcp listener, on a backend and on a fastcgi route.
- **`read`** (text): On an http or https listener: how long a client may pause while it sends a request body (default 60s). On a backend: how long a server may stay silent once it has started to answer (no limit unless set). A transfer that keeps moving is never cut. "0": no limit. Refused on a tcp listener and on a fastcgi route.
- **`write`** (text): On an http or https listener: how long a client may pause while it takes a response. Default 60s. A download that keeps moving is never cut. "0": no limit. Refused on a tcp listener, on a backend and on a fastcgi route.
- **`idle`** (text): How long a connection may stay idle on a listener: on http and https a kept-alive connection between requests (default 120s; the listeners on one bind address share the largest they set); on tcp, with tls or without, a connection with no traffic either way (default 5m). "0": no limit. Refused on a backend and on a fastcgi route.
- **`response_header`** (text): On a backend, or a fastcgi route: how long a server may take to start answering once it has the request. Default 60s, then 504. Refused on a listener. "0": no limit.

## `listeners[].tls`

- **`cert`** (text): The certificate file (PEM), with its chain. Read again on a reload, so a renewed certificate is taken without a restart.
- **`key`** (text): The private key file (PEM) of the certificate.
- **`auto_cert`** (true or false): Not built yet: a listener that sets it to true is refused at load.
- **`ocsp_stapling`** (true or false): Not built yet: a listener that sets it to true is refused at load.
- **`client_auth`** (text): Client certificates: require (the handshake fails without one that client_ca verifies), request (asked for, not required) or none (the default). On a bind address shared by several https listeners, each listener has its own, chosen by the server name; a request whose Host names a listener that requires one, on a connection that began with another's name, is answered 421.
- **`client_ca`** (text): The file (PEM) of the certificate authorities that client certificates are verified with. Required by client_auth: require; refused without client_auth.
- **`min_version`** (text): The lowest TLS version accepted: 1.2 (the default) or 1.3.
- **`max_version`** (text): The highest TLS version accepted: 1.2 or 1.3 (the default).
- **`cipher_suites`** (list of text): The cipher suites allowed for TLS 1.2, by their standard names, such as TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256. Empty: a safe default list. TLS 1.3 has fixed suites.

## `listeners[].sni_routes[]`

- **`server_name`** (text): Not built yet: a listener with sni_routes is refused at load.
- **`backend`** (text): Not built yet: a listener with sni_routes is refused at load.

## `listeners[].ip_rate_limit`

- **`requests_per_second`** (number): The requests a second each client address may make over time; past it a request is answered 429. 0 (the default): no limit.
- **`burst`** (number): How many requests a client address may make at once before the rate counts. Default 1.

## `listeners[].acl[]`

- **`match`** (section): What a request must be for the rule to apply: every condition set must hold.
- **`action`** (text): What the rule does to a request it matches: allow or deny.
- **`status`** (number): The status a deny rule answers with. Default 403; 404 hides that the path exists. Not used by an allow rule.

## `listeners[].acl[].match`

- **`source_ip`** (list of text): Client addresses and ranges ("10.0.0.0/8"); the client as ip_allowlist sees it.
- **`method`** (list of text): Request methods, such as GET or POST. Not on tcp and udp listeners.
- **`headers`** (map of text to text): Request headers and the values they must have. Not on tcp and udp listeners.
- **`path_prefix`** (text): The start of the request path, such as "/admin". The path is read as the backend reads it ("//admin" and "/x/../admin" are "/admin"), and case matters. Not on tcp and udp listeners.
- **`path_regex`** (text): A regular expression (RE2) the request path must match, such as "^/admin(/|$)", which leaves "/administrator" alone. Not on tcp and udp listeners.

## `listeners[].routes[]`

- **`match`** (section): The requests the route takes: every condition set must hold.
- **`backend`** (text): The backend the route's requests go to, by its name. Required unless the route redirects, serves files or passes to FastCGI.
- **`headers`** (section): Request and response headers added, set or removed for the route's requests, after the listener's.
- **`rewrite`** (section): A new path for the request on its way to the backend.
- **`redirect`** (section): Answers the route's requests with a redirect.
- **`scripts`** (section): Not built yet: a route that sets it is refused at load.
- **`static`** (section): Serves the route's requests from files.
- **`try_files`** (section): Files tried in turn for a request, as nginx's try_files does.
- **`expires`** (text): Cache-Control and Expires of the route's answers: a time such as "1y", "30d", "1h" or "10m"; "-1" for never kept; "epoch" for already expired; "off" or empty to leave the headers as they are.
- **`fastcgi`** (section): Passes the route's requests to a FastCGI server, such as PHP-FPM.

## `listeners[].routes[].match`

- **`host`** (text): The request's host name, exactly, in any case.
- **`path_prefix`** (text): The start of the request path, such as "/api/".
- **`path_regex`** (text): A regular expression (RE2) the request path must match; its groups can be used as $1, $2 in rewrite.path and redirect.url.

## `listeners[].routes[].headers`

- **`request_add`** (map of text to text): Headers added to the request on its way to the backend, next to those of the same name it has.
- **`request_set`** (map of text to text): Headers set on the request on its way to the backend, in place of those of the same name.
- **`request_remove`** (list of text): Headers removed from the request on its way to the backend.
- **`response_add`** (map of text to text): Headers added to the response on its way to the client.
- **`response_set`** (map of text to text): Headers set on the response on its way to the client, in place of those of the same name.
- **`response_remove`** (list of text): Headers removed from the response on its way to the client.

## `listeners[].routes[].rewrite`

- **`path`** (text): The path the backend is asked for instead of the request's, with $1, $2 for the groups of match.path_regex, such as "/v2/$1".

## `listeners[].routes[].redirect`

- **`url`** (text): Where the redirect points, with ${scheme}, ${host}, ${port}, ${path}, ${query} and ${uri} of the request, and $1, $2 for the groups of match.path_regex: "https://${host}${uri}", say.
- **`code`** (number): The redirect's status code. Default 302.

## `listeners[].routes[].scripts`

- **`request_script`** (text): Not built yet: a route that sets it is refused at load.
- **`response_script`** (text): Not built yet: a route that sets it is refused at load.

## `listeners[].routes[].static`

- **`root`** (text): The directory files are served from: a request's path names a file under it, and never one outside it.
- **`index`** (list of text): The files served for a directory, in order. Default index.html.
- **`autoindex`** (true or false): Lists a directory that has no index file.

## `listeners[].routes[].try_files`

- **`files`** (list of text): The files tried in order under static.root, the first that exists served: $uri is the request path, $uri/ the directory with its index, $args the query, $is_args "?" when there is one. Such as ["$uri", "$uri/", "/index.php$is_args$args"].
- **`fallback`** (text): What answers when no file exists: "=404" (a status), or a path, such as "/index.php", served by the same route.

## `listeners[].routes[].fastcgi`

- **`pass`** (text): The FastCGI server's address: "127.0.0.1:9000", or a socket file as "unix:/run/php/php-fpm.sock".
- **`document_root`** (text): The directory the scripts lie in, as the FastCGI server sees it, and nvelox at the same path. Required: only a .php file that exists in it is run.
- **`script_name`** (text): SCRIPT_NAME as the script is told it. Default: from the request path.
- **`split_path_info`** (text): A regular expression that splits the path into the script and PATH_INFO, as nginx's fastcgi_split_path_info does, such as "^(.+\.php)(/.+)$".
- **`params`** (map of text to text): More FastCGI parameters, by name.
- **`index`** (text): Not built yet: a route that sets it is refused at load. try_files names the script a request falls back to.
- **`timeouts`** (section): Two timeouts apply to a FastCGI server: connect (how long the connection to it may take: default the listener's, else 10s; 502 when it fails) and response_header (how long it may take to start answering once it has the request: default 60s, then 504). The others are refused here.

## `listeners[].routes[].fastcgi.timeouts`

- **`connect`** (text): How long opening a connection to a server may take, such as "5s": a backend's own, else its listener's, else 10s. When it fails a request is answered 502, a tcp client's connection closed. "0": no limit.
- **`read_header`** (text): On an http or https listener: how long a client may take to send a request's head. Default 10s. The listeners on one bind address share one value, the largest they set. "0": no limit. Refused on a tcp listener, on a backend and on a fastcgi route.
- **`read`** (text): On an http or https listener: how long a client may pause while it sends a request body (default 60s). On a backend: how long a server may stay silent once it has started to answer (no limit unless set). A transfer that keeps moving is never cut. "0": no limit. Refused on a tcp listener and on a fastcgi route.
- **`write`** (text): On an http or https listener: how long a client may pause while it takes a response. Default 60s. A download that keeps moving is never cut. "0": no limit. Refused on a tcp listener, on a backend and on a fastcgi route.
- **`idle`** (text): How long a connection may stay idle on a listener: on http and https a kept-alive connection between requests (default 120s; the listeners on one bind address share the largest they set); on tcp, with tls or without, a connection with no traffic either way (default 5m). "0": no limit. Refused on a backend and on a fastcgi route.
- **`response_header`** (text): On a backend, or a fastcgi route: how long a server may take to start answering once it has the request. Default 60s, then 504. Refused on a listener. "0": no limit.

## `listeners[].headers`

- **`request_add`** (map of text to text): Headers added to the request on its way to the backend, next to those of the same name it has.
- **`request_set`** (map of text to text): Headers set on the request on its way to the backend, in place of those of the same name.
- **`request_remove`** (list of text): Headers removed from the request on its way to the backend.
- **`response_add`** (map of text to text): Headers added to the response on its way to the client.
- **`response_set`** (map of text to text): Headers set on the response on its way to the client, in place of those of the same name.
- **`response_remove`** (list of text): Headers removed from the response on its way to the client.

## `listeners[].compression`

- **`enabled`** (true or false): Turns gzip compression on, for the clients that accept it.
- **`types`** (list of text): The content types compressed. Default text/html, text/css, text/plain, text/xml, application/json, application/javascript and application/xml.
- **`min_length`** (number): The smallest response compressed, in bytes, read from its Content-Length; a response without one is compressed. 0 (the default): every size.

## `listeners[].buffering`

- **`request_body_buffer`** (text): Not built yet: a listener that sets it is refused at load.
- **`response_buffer`** (text): The size of the buffer each response body is copied through, such as "256KB", for the sites the event loops hand to the Go HTTP server: those that compress, cache, or ask for client certificates. Default 32KB. The event loops relay with buffers of their own.

## `listeners[].cache`

- **`enabled`** (true or false): Turns the cache on for the listener's responses.
- **`max_size`** (text): The most memory the cache holds, such as "256MB". Default 64MB. One response is kept only up to 8MB, or up to max_size when that is smaller.
- **`default_ttl`** (text): How long a response stays in the cache, such as "5m". Default 5m. Responses marked no-cache, no-store or private, and those that set a cookie, are not kept.
- **`methods`** (list of text): The request methods whose responses are kept. Default GET.

## `listeners[].throttle`

- **`read_rate`** (text): Not built yet: a listener that sets it is refused at load.
- **`write_rate`** (text): Not built yet: a listener that sets it is refused at load.

## `listeners[].request_id`

- **`enabled`** (true or false): Turns request IDs on.
- **`trust_inbound`** (true or false): Keeps the X-Request-ID a request arrives with from any client, when it is well formed. Off (the default), it is kept only from trusted_proxies and replaced otherwise, so that a client cannot choose its ID. For internal listeners whose callers carry an ID.

## `backends[]`

- **`name`** (text): The backend's name, which listeners and routes refer to. Required, and one to a backend.
- **`balance`** (text): How a server is picked for each connection or request: roundrobin (the default) in turn, leastconn the one with the fewest open, random at random.
- **`send_proxy_v2`** (true or false): Begins every connection to the servers, and every datagram, with a PROXY protocol version 2 header that names the client. The server must expect it on every connection.
- **`send_proxy_key_file`** (text): Signs that header with the first key of this file (as a listener's accept_proxy_key_file holds them), for a receiver that checks it. Signed in version 2: nvelox 1.3.0 and older, and 2.0.0-rc.3 and older, refuse it, so upgrade the receivers first. Needs send_proxy_v2.
- **`servers`** (list of text): The servers' addresses, such as "10.0.0.5:8080" or "app.internal:8080"; a server without a port takes the listener's.
- **`max_connections`** (number): The most HTTP requests, TCP connections or UDP sessions the backend serves at once: past it a request is answered 503, a connection or session refused. 0 (the default): no limit.
- **`timeouts`** (section): How long a server gets to accept a connection, to start answering and to stay silent once it has started.
- **`retry`** (section): Trying another server when the first fails.
- **`sticky_session`** (section): Keeping a client on the server it began with.
- **`resolve_interval`** (text): Makes nvelox look the servers' names up itself, at this interval, such as "30s", and spread the traffic over every address a name has. Empty: a name is looked up as each connection to it is opened.
- **`allow_private_ips`** (true or false): With resolve_interval: lets the servers, by address or by name, be private addresses (10.0.0.0/8 and the other private ranges, loopback, link-local, carrier-grade NAT). Off (the default), such an address is left out and logged, so that a name someone else controls cannot point nvelox into your network. Turn it on when the servers are on a private network.
- **`backend_tls`** (section): TLS to the servers, for http and https listeners.
- **`circuit_breaker`** (section): Stops sending to the backend for a while after failures in a row.
- **`health_check`** (section): Checks that take a failing server out of the rotation, and bring it back.

## `backends[].timeouts`

- **`connect`** (text): How long opening a connection to a server may take, such as "5s": a backend's own, else its listener's, else 10s. When it fails a request is answered 502, a tcp client's connection closed. "0": no limit.
- **`read_header`** (text): On an http or https listener: how long a client may take to send a request's head. Default 10s. The listeners on one bind address share one value, the largest they set. "0": no limit. Refused on a tcp listener, on a backend and on a fastcgi route.
- **`read`** (text): On an http or https listener: how long a client may pause while it sends a request body (default 60s). On a backend: how long a server may stay silent once it has started to answer (no limit unless set). A transfer that keeps moving is never cut. "0": no limit. Refused on a tcp listener and on a fastcgi route.
- **`write`** (text): On an http or https listener: how long a client may pause while it takes a response. Default 60s. A download that keeps moving is never cut. "0": no limit. Refused on a tcp listener, on a backend and on a fastcgi route.
- **`idle`** (text): How long a connection may stay idle on a listener: on http and https a kept-alive connection between requests (default 120s; the listeners on one bind address share the largest they set); on tcp, with tls or without, a connection with no traffic either way (default 5m). "0": no limit. Refused on a backend and on a fastcgi route.
- **`response_header`** (text): On a backend, or a fastcgi route: how long a server may take to start answering once it has the request. Default 60s, then 504. Refused on a listener. "0": no limit.

## `backends[].retry`

- **`attempts`** (number): How many servers a request tries, the first included. Default 1: no retry.
- **`on`** (text): When a request tries the next server, separated by commas: connect_failure (the server could not be reached), 502, 503. Default connect_failure.

## `backends[].sticky_session`

- **`type`** (text): What keeps a client on its server: cookie (one nvelox sets), header (one the client sends) or ip_hash (its address). Empty: none.
- **`cookie_name`** (text): The cookie's name for type cookie. Default NVELOX_SRV.
- **`header_name`** (text): The header's name for type header.
- **`ttl`** (text): How long a client stays on its server without a request, such as "1h". Default 1h.

## `backends[].backend_tls`

- **`enabled`** (true or false): Connects to the servers over TLS. A backend that cannot build its TLS settings stops the start or the reload: nvelox never falls back to plain text. For http and https listeners only.
- **`ca_cert`** (text): The file (PEM) of the certificate authorities the servers' certificates are verified with. Empty: the system's.
- **`client_cert`** (text): The certificate file (PEM) nvelox presents to servers that ask for one.
- **`client_key`** (text): The private key file (PEM) of client_cert.
- **`insecure`** (true or false): Accepts any certificate from the servers, without verifying it: for tests, never across a network you do not control. A warning says so at start.
- **`server_name`** (text): The name sent to the servers (SNI) and checked on their certificates. Empty: the host of each server's address.

## `backends[].circuit_breaker`

- **`enabled`** (true or false): Turns the circuit breaker on.
- **`threshold`** (number): How many failed requests in a row open the breaker: the backend's requests are then answered 503 at once.
- **`timeout`** (text): How long the breaker stays open before it lets requests try again, such as "30s". Default 30s.
- **`half_open_max`** (number): How many requests may try at once when the breaker lets them; success closes it, failure opens it again. Default 1.

## `backends[].health_check`

- **`active`** (section): Checks nvelox makes of every server at an interval: a server that fails one is out of the rotation until it passes one.
- **`passive`** (section): Takes a server out of the rotation after failed requests in a row.

## `backends[].health_check.active`

- **`type`** (text): What a check is: tcp (the default) opens a connection; http asks for path and wants a status from 200 to 399.
- **`path`** (text): The path an http check asks for, such as "/healthz".
- **`interval`** (text): How often each server is checked, such as "10s". Active checks run only when it is set.
- **`timeout`** (text): How long a check may take, such as "2s". Default 1s.

## `backends[].health_check.passive`

- **`max_fails`** (number): How many failed requests in a row take a server out of the rotation, for 30 seconds; it then takes traffic again, and its next failure takes it out again. When every server is out, they are all used. 0 (the default): off.
