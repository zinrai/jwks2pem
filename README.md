# jwks2pem

A command-line tool that fetches a JSON Web Key Set (JWKS) and writes its signing keys as PEM public keys, for JWT verifiers that read keys only from files, such as HAProxy's `jwt_verify`.

It keeps the files in step with the JWKS: run it on a timer, and when the identity provider rotates its keys, the files change; when it has not, nothing is written. A run that cannot fetch the JWKS exits non-zero and leaves the files as they were.

## Usage

```bash
$ jwks2pem -url https://idp.example/keys -out /etc/haproxy/jwt -slots 4
/etc/haproxy/jwt/1.pem
/etc/haproxy/jwt/2.pem
/etc/haproxy/jwt/3.pem
/etc/haproxy/jwt/4.pem
```

| Option | Required | Description |
|---|---|---|
| `-url <url>` | yes | The JWKS |
| `-out <dir>` | yes | Directory to write `1.pem` to `<slots>.pem` into |
| `-slots <n>` | yes | Number of files to write |
| `-cacert <file>` | no | CA certificate to trust for the URL, instead of the system's |

Set `-slots` to the most signing keys your provider publishes at once, rotation included; some publish the next key ahead of its use. More keys than slots is an error. The files hold the keys in no meaningful order, and slots beyond the keys repeat one, so configure the verifier to try every file.

To reload the verifier only when a key changed, let something watch the directory, such as a systemd path unit:

```ini
# jwks2pem.service, started by a timer
[Service]
Type=oneshot
ExecStart=/usr/local/bin/jwks2pem -url https://idp.example/keys -out /etc/haproxy/jwt -slots 4

# haproxy-jwt.path
[Path]
PathChanged=/etc/haproxy/jwt
Unit=haproxy-reload.service
```

## License

This project is licensed under the [MIT License](./LICENSE).
