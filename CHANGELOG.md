# Changelog

## [1.0.14] - 2021-07-13

- Send auth packet to all ips a hostname resolves to

## [1.0.13] - 2021-06-30

- Do not warn on empty public ip cache file
- The public ip cache file path can be controlled using the `SPAROID_CACHE_PATH` environment variable

## [1.0.12] - 2021-06-14

- Use file locking to prevent multiple processes/threads to write to the public ip cache file

## [1.0.11] - 2021-06-14

- Log hostname when reporting unhandled exceptions

## [1.0.10] - 2021-06-09

- Cache public IP in `/tmp/.sparoid_public_ip` for 1 min

## [1.0.9] - 2021-05-23

- Exit gracefully on abort (ctrl-c) instead of dumping huge stacktrace
- Sleep 20ms aftering sending UDP package to allow for remote host to open its firewall

## [1.0.8] - 2021-04-27

- Get ENV variables if config file is missing

## [1.0.7] - 2021-04-27

- Get key and hmac key from ENV variables

## [1.0.6] - 2021-04-13

- Use static IP for opendns resolver, saves one DNS lookup

## [1.0.5] - 2021-04-12

- Prefix all logging with `Sparoid:`

## [1.0.4] - 2021-03-25

- Only warn if config is missing when connecting with CLI

## [1.0.3] - 2021-03-17

- Nicer error handling in CLI, remove --fdpass option

## [1.0.2] - 2021-03-15

- `sparoid send` renamed to `sparoid auth`
- `sparoid connect [host] [port]` added for automatic fd passing

## [1.0.1] - 2021-03-12

- --fdpass option to send

## [1.0.0] - 2021-03-11

- Initial release
