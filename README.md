# yksoft

[![CI build status][BuildStatus]][BuildStatusLink]

## Introduction

Sometimes it's useful to emulate a physical Yubikey token in software, examples of this include:

- Testing, where you don't want to purchase a Yubikey.
- M2M VPN connections where the other party is unable to make an exception to
  their 2FA policy.
- Particularly difficult customers who want to treat everyone in your organisation as
  their employees, and want to issue each of them a hardware token to connect into
  their VPN service.

Yubico provides the `ykgenerate` utility which emulates most of a hardware based
Yubikey's HOTP functionality.  Unfortunately `ykgenerate` doesn't persist counter
information, track time between OTP code generation, and many other small bits and
pieces that are needed to properly emulate a hardware token.

**NOTE**

yksoft is not intended to be a replacement for a Yubikey in situations that require
high security, this utility is not as secure as a proper physical key.

## Building

yksoft has a single 3rd party dependency which is `libyubikey`.
yksoft also requires the `arc4random` functions provided by the BSD standard library.

### macos

```bash
brew install libyubikey
make
```

### Debian/Ubuntu

```bash
sudo apt-get install libyubikey-dev libbsd-dev
make
```

### RHEL/Rocky etc...

```bash
yum install libyubikey-devel libbsd-devel
make
```

## First use

yksoft by default will search in `~/.yksoft` for a token persistence file `default`.
If this file is not found, a new public id, private id, and AES key is generated and
written to the `~/.yksoft/default` along with various timestamps and counters.

The token persistence file is not encrypted in any way, and you should ensure that
permissions on it are set correctly, i.e. NOT world readable/writable.  yksoft will
refuse to run with incorrect permissions.

When the token persistence file is created, data needed to register the soft token
with an authentication server is written to stdout and no OTP is produced.

```bash
> yksoft
public_id_modhex: ddddjkdcungg
public_id_hex: 22228920eb55
public_id_dec: 37531724868437
private_id_modhex: bclcegdnhdvn
private_id_hex: 10a0352b62fb
private_id_dec: 18280272847611
aes_key_hex: 622708a469ece555bd1fc3ee20c3222a
```

Subsequent calls (where the token persistence file exists) will write an OTP to
stdout.

```bash
> yksoft
ddddjkdcunggjfnkgjedvntebkukhejnbffchurkgruc
```

If you need to see the registration information again, either cat the persistence file
(it's there as plaintext), or pass the `-r` flag.

## Usage patterns
### Emulating an existing physical token

If the public identity, private identity, AES key, and counter of an existing token 
are known they can be passed in via `-I <modhex>`, `-i <hex>`, `-k <hex>` and 
`-c <uint>` respectively.

These values will be written to the persitence file instead of random values being used.

The value passed in via `-c` is always incremented by 1, to "reset" the session count.

### Public ID prefixes

Where a public identity is specified with `-I` any identity bytes not provided on the 
command line, will be filled with random bytes.  Passing `-I frfr` for example, would 
produce a public identity with a `frfr` prefix e.g. `frfrttuhdgvb`.

### Using multiple tokens

The final parameter passed to yksoft determines the name of the token file used.

```bash
> yksoft foo
# Loads token persistence data from ~/.yksoft/foo
```

The default token directory may be altered with the `-f` argument.

```bash
> yksoft -f /tmp/ foo
# Loads persistence data from /tmp/foo
```

### Logging

For robustness when calling yksoft from a VPN client, debugging output goes to stderr, 
only the OTP token and registration information is written to stdout.

Debug logging may be enabled with `-d`.

## Technical details
### Time

A hardware based Yubikey has an 8hz timer that runs whenever the key is powered on.
This lets the authenticator detect out of order uses of tokens.

In a hardware token, the initial timer value is set to a random value when the token
is powered on. As yksoft is never "powered off", we pick a new random timer value
(`ponrand`) whenever the use counter is incremented by one (i.e. when the session
counter wraps).

We calculate time as `(((time() - created) * 8) + ponrandom) % 0xffffff`,
where `ponrandom` is 28 bits of randomness, and 4bits of sub-second use counter.

`time()` and friends only have a resolution of seconds, and accessing the high resolution
functions on various platforms is a pain. To allow multiple token codes to be generated
in the same second, we reserve one nibble in `ponrandom` and increment that each time yksoft
is executed, and `lastuse` is equal to `time()`.

When `lastuse` is no longer equal to `time()`, the sub-second use counter is reset to 0.

If the sub-second use counter reaches 7, we sleep for one second before generating the OTP.

### Anatomy of a persistence file

The persistence file consists of key/value pairs separated by `: `, terminated by `\n`.

Keypairs

| Name         | Format   | Length  | Description                                                            |
|--------------|----------|---------|------------------------------------------------------------------------|
| `public_id`  | modhex   | 12      | Public ID prepended to the OTP.                                        |
| `private_id` | hex      | 12      | Private ID used to validate the OTP.                                   |
| `aes_key`    | hex      | 32      | Key used to encrypt the Private ID and other fields.                   |
| `counter`    | uint15   |         | Usage counter used to track power on events and session counter wraps. |
| `session`    | uint8    |         | How many OTPs we've generated since `counter` was last incremented.    |
| `created`    | time_t   |         | Unix timestamp indicating when the token was initialised.              |
| `lastuse`    | time_t   |         | Unix timestamp indicating when the token was last used.                |
| `ponrand`    | uint32   |         | Random number chosen the last time `counter` was incremented.          |

If any of these keys are not found in the persistence file, their value will be treated as 0.

[BuildStatus]: https://github.com/arr2036/yksoft/actions/workflows/ci-linux.yml/badge.svg "CI status"
[BuildStatusLink]: https://github.com/arr2036/yksoft/actions/workflows/ci-linux.yml
