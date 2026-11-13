# zoraxy-method-filter

A plugin for the [Zoraxy](https://github.com/tobychui/zoraxy) reverse proxy that adds a
**per-host allow-list of HTTP methods**.

Zoraxy forwards every HTTP method to the upstream. With this plugin you choose, for each
proxy host, which methods may reach the backend; anything else is answered by the plugin
and never forwarded. It is the equivalent of the common nginx hardening rule

```nginx
if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE)$) { return 444; }
```

Tested with Zoraxy v3.3.4.

## Features

- Allow-list of methods per proxy host: checkboxes for the standard methods, plus a free
  field for others (e.g. `PROPFIND`, `MKCOL` for WebDAV).
- Optional refusal of HTTP/1.0 requests, per host.
- Selectable answer for refused requests: `405` (with an `Allow` header), `403`, `400` or `404`.
- Alias hostnames use the rule of their host. Hosts without an enabled rule are not filtered.
- Everything is configured from the plugin UI inside Zoraxy, with search and filters so it stays
  usable with hundreds of hosts (a `#hostname` in the page URL opens it on that host); rules apply as soon as they are
  saved. No file to edit.
- Per-host counters (passed / refused, last refused request) to see that the filter is working.

## Install

From the Zoraxy plugin store (once listed), or manually:

1. Download the binary for your platform from the [releases](https://github.com/fdefilippo/zoraxy-method-filter/releases/latest).
2. Create a folder in the Zoraxy plugin directory and put the binary in it **with the same
   name as the folder**, e.g. `plugins/org.defilippo.zoraxy.methodfilter/org.defilippo.zoraxy.methodfilter`,
   and make it executable.
3. Restart Zoraxy (new plugins are detected at start-up).

## Setup

1. **Plugins**: enable *HTTP Method Filter* and attach it to a tag (for example `method-filter`).
2. **HTTP Proxy**: add that tag to every host you want to filter.
3. **Plugins → HTTP Method Filter**: turn on *Filter methods* for each host, pick the allowed
   methods and save.

A host with an enabled rule that shows "no request seen yet" is usually missing the tag.

## How it works

The plugin uses Zoraxy's *dynamic capture*: for every request of a tagged host Zoraxy sends
method, protocol and hostname to the plugin. Allowed requests are skipped and continue to
the virtual directories and the upstream as usual; refused ones are captured and answered by
the plugin. The check runs after Zoraxy's access rules and authentication.

The plugin only needs one Zoraxy API endpoint, `POST /plugin/api/proxy/list`, to show the list
of hosts in its UI. Rules are stored in `method-filter.json` in the plugin folder.

## Limitations

- **Fail-open.** If the plugin crashes, Zoraxy disables it and requests are forwarded
  unfiltered until it is enabled again. `deploy/zoraxy-method-filter-check.sh` is an optional
  cron watchdog that detects this.
- It cannot drop the connection without answering (nginx `444`); refused requests get an
  HTTP error status.
- It applies to tagged proxy hosts only, not to the default site.
- Every request of a tagged host costs one extra local round trip to the plugin.

## Build

```sh
./build.sh           # tests + linux/amd64 binary in build/
./build.sh release   # all architectures in dist/
```

Requires Go 1.23 or newer.

## License

AGPL-3.0, see [LICENSE](LICENSE). `mod/zoraxy_plugin` is the Zoraxy plugin SDK, copied from
the Zoraxy source tree (v3.3.4), also AGPL-3.0.

Author: Defilippo srl — info@defilippo.org
