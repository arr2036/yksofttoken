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
high security, this utility is not as secure as a physical Yubikey.

## Building

yksoft has a single 3rd party dependency which is `libyubikey`.

### macos

```bash
brew install libyubikey
make
```

### Debian/Ubuntu

```bash
sudo apt-get install libyubikey-dev
make
```

### RHEL/Rocky etc...

```bash
yum install libyubikey-devel
make
```

## First use

yksoft by default will search in `~/.yksoft` for a token persistence file `default`.
If this file is not found, a new public id, private id, and AES key is generated and
written to `~/.yksoft/default` along with various timestamps and counters.

The token persistence file is not encrypted in any way, and you should ensure that
permissions on it are set correctly, i.e. NOT world readable/writable.  yksoft will
refuse to run with incorrect permissions.

When the token persistence file is created, data needed to register the soft token
with an authentication server is written to stdout and no OTP is produced.

```bash
> yksoft
ddddjkdcungg, 10a0352b62fb, 622708a469ece555bd1fc3ee20c3222a
```

Subsequent calls (where the token persistence file exists) will write an OTP to
stdout.

```bash
> yksoft
ddddjkdcunggjfnkgjedvntebkukhejnbffchurkgruc
```

If you need to see the registration information again, either cat the persistence file
(it's there as plaintext), or pass the `-r` flag.

## Arguments

See the output of `yksoft -h`, currently:

```text
usage: ./yksoft [options] [<token file>]

  -C <counter_cmd>        Run a persistence command when a new token is generated, or when the 'use' counter increments.

  -c <counter>            Counter for initialisation (0-32766).  Will always be incremented by one on first use.  Defaults to 0.

  -I <public_id>          Public ID as MODHEX to use for initialisation (max 6 bytes i.e. 12 modhexits).  Defaults to dddd<4 byte random>.
                          If the Public ID is < 6 bytes, the remaining bytes will be randomised.

  -i <private_id>         Private ID as HEX to use for initialisation (6 bytes i.e. 12 hexits).  Defaults to <6 byte random>.

  -k <key>                AES key as HEX to use for initialisation (16 bytes i.e. 32 hexits).  Defaults to <16 byte random>.

  -d                      Turns on debug logging to stderr.

  -f                      Specify the directory tokens are stored in.  Defaults to "~/.yksoft"

  -r                      Prints out registration information to stdout. An OTP will not be generated.

  -R                      Regenerate the specified token.

  -h                      This help text.

Emulate a hardware yubikey token in HOTP mode.
```

## How do I...
### Emulate an existing physical token

If the public identity, private identity, AES key, and counter of an existing token
are known they can be passed in via `-I <modhex>`, `-i <hex>`, `-k <hex>` and
`-c <uint>` respectively.

These values will be written to the persitence file instead of random values being used.

The value passed in via `-c` is always incremented by 1, to "reset" the session count.

### Generate a public ID from a prefix

Where a public identity is specified with `-I`, any identity bytes not provided on the
command line will be filled with random bytes.  Passing `-I frfr` for example, would
produce a public identity with a `frfr` prefix e.g. `frfrttuhdgvb`.

### Use multiple tokens

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

### Restore a token from a backup

Four pieces of information are needed to restore a soft token, the `public_id`,
`private_id`, `aes_key` and `counter`.

The first three values are static and should be retrieved from a secure password manager
and passed in via `-I`, `-i` and `-k` respectively.

`counter` will increment every 255 OTPs generated.  When the counter value is incremented
the new counter value should be recorded off-box.

If the `-C` argument is provided, whenever `counter` increments, or a new token is
generated, the command specified with `-C` is passed as an argument to `/bin/sh -c`
(or whichever shell is specified by `$SHELL`).

The contents of the token persistence file is made available as environmental variables.
For example `${counter}` contains the new `counter` value, and `${public_id}` contains
the `public_id` of the token.

It's left as an exercise to the user on how to persist this counter to a remote system.

When restoring from a backup the last known counter value should be passed in via `-c`.

## Logging

For robustness when calling yksoft from a VPN client, debugging output goes to stderr,
only the OTP token and registration information is written to stdout.

Debug logging may be enabled with `-d`.

## VPN clients
### Openconnect

The easiest way to submit both factors to openconnect is via `--password-on-stdin`.
In the example below we pipe in the first factor, then the output of yksoft separated
by the newline from echo.  You could also `cat` the first factor from a file.

```bash
(echo '<first factor>'; yksoft [<token file>]) | openconnect --user=<user> <url> --passwd-on-stdin
```

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

[BuildStatus]: https://github.com/arr2036/yksofttoken/actions/workflows/ci-linux.yml/badge.svg "CI status"
[BuildStatusLink]: https://github.com/arr2036/yksofttoken/actions/workflows/ci-linux.yml
