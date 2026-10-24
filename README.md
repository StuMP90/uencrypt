# uEncrypt

Post-quantum file encryption and signing for Linux and Windows, with a
command-line tool for scripts and servers and a desktop app for everyday use.

uEncrypt replaces the older `ppkencrypt`/`ppkdecrypt` CLI and the Fyne
desktop app, and still decrypts every file they produced.

## Features

- **Post-quantum encryption.** By default new keys are hybrid ML-KEM-768 +
  X25519, so a file is safe unless both algorithms are broken.
- **Standard format.** Encrypted files are ordinary [age](https://age-encryption.org)
  v1 files (`.age`). Unsigned files can be decrypted by any age v1.3+ tool,
  such as `age` or `rage`.
- **Signing.** Hybrid ML-DSA-65 + Ed25519 signatures. You can make detached
  `.sig` files with `sign`, or sign inside the encrypted file with `encrypt -s`.
- **Optional passphrases.** Keys can be stored without a passphrase, and
  encrypting to a public key never asks for one. This suits unattended
  backups.
- **Legacy support.** Import the old RSA `.pem` keys to decrypt `.enc`
  files. Both the original and the chunked formats are supported. Legacy
  keys can only decrypt; new files always use age.
- **Safe output.** Output is written under a temporary name. It is renamed
  only after the file has been fully decrypted and any required signature
  has been verified, so a failed run never leaves a partial file behind.

## Quick start

```sh
uencrypt keys new me                  # create your identity (becomes the default)
uencrypt encrypt report.pdf           # -> report.pdf.age, encrypted to yourself
uencrypt decrypt report.pdf.age       # -> report.pdf

uencrypt keys export me > me.contact  # give this to people who send you files
uencrypt keys import alice.contact    # add a contact
uencrypt encrypt -r alice -s data.tar # encrypt to alice and sign it as you
uencrypt decrypt --signer me data.tar.age   # on alice's side: require my signature

uencrypt sign release.zip             # -> release.zip.sig
uencrypt verify release.zip.sig
uencrypt inspect somefile             # what is it, who can open it?
```

Run `uencrypt COMMAND -h` to see each command's options.

### Old `.enc` files

```sh
uencrypt keys import old-private.pem --name oldkey
uencrypt decrypt backup.tar.gz.enc    # -> backup.tar.gz
```

You can also pass a key for one run only with `--legacy-key FILE.pem`,
without importing it.

### Inspecting files

`uencrypt inspect FILE...` describes files without changing them:

- **`.age` files:** the recipient types and counts, and whether the file is
  post-quantum. It also shows the sizes (header, payload and overhead),
  whether the file is armored, and whether one of your keys can open it.
  SSH recipients are matched to your `~/.ssh` keys and contacts. The age
  format does not record which other keys a file is for.
- **Old `.enc` files:** the format (original or chunked), the RSA key size,
  the chunks, and which imported legacy key opens the file. For chunked
  files it notes that their end is not authenticated.
- **`.sig` signatures:** who signed the file, and when.
- **Other files:** what kind of file it is, with the entries of zip and tar
  archives, including `.tar.gz` and `.tar.bz2`. Other compressed files
  (xz, zstd) are recognised but not listed.

```sh
uencrypt inspect backup.tar.gz.age old.enc
uencrypt inspect --contents backup.tar.gz.age   # decrypt in memory: contents, signer
uencrypt inspect --json *.age                   # for scripts
```

`--contents` decrypts the file in memory to show what it holds and whether
it is signed. It saves nothing. In the desktop app, click ⓘ next to a file,
then "Look inside…".

### SSH keys

As with `age`, you can encrypt to someone's `ssh-ed25519` or `ssh-rsa` public
key, and decrypt with your own SSH private key:

```sh
uencrypt encrypt -R ~/.ssh/id_ed25519.pub file.txt     # or -r "ssh-ed25519 AAAA..."
uencrypt encrypt -R authorized_keys file.txt           # one key per line
uencrypt keys import bob.pub                           # a contact named from its comment
uencrypt decrypt file.txt.age                          # tries ~/.ssh/id_ed25519 and id_rsa
uencrypt decrypt -i ~/.ssh/work_key file.txt.age
```

If the SSH private key has a passphrase, you are asked for it only when a file
is actually encrypted to that key. SSH private keys stay where they are: they
are never copied into the keyring. SSH keys are classic (not post-quantum), so
they cannot be mixed with post-quantum recipients in one file. They cannot
sign either. Files encrypted this way are readable by `age -i` and vice versa.

In the desktop app, import a `.pub` file (or paste the key) on the Keys page.
You can also paste the key into "Other public keys" on the Encrypt page. To
decrypt with a key other than the standard two, use "Use an SSH key…" on the
Decrypt page.

## Automated backups

Server use is supported on Linux. Create the key that will encrypt the
backups on the machine that will *decrypt* them. Then import only its public
contact on the server. The server never holds anything that can read the
backups.

```sh
# on the restore machine
uencrypt keys new backup-restore
uencrypt keys export backup-restore > backup-restore.contact

# on the server (no passphrase needed to encrypt)
uencrypt keys import backup-restore.contact
tar czf - /etc | uencrypt encrypt -q -r backup-restore -o /var/backups/etc.tgz.age -
```

To sign backups as well, create an unlocked signing identity on the server
with `keys new server --no-passphrase`, then add `-s`.

| Variable | Purpose |
|---|---|
| `UENCRYPT_PASSPHRASE` | passphrase for `-p` (passphrase-encrypted) files |
| `UENCRYPT_KEY_PASSPHRASE` | passphrase for locked identities |
| `UENCRYPT_KEYRING` | keyring directory (or use `--keyring DIR`) |

Exit status: `0` ok, `1` error, `2` usage, `3` signature invalid or missing,
`4` no key can decrypt the file.

## Compatibility notes

- **Signed and encrypted files** (`encrypt -s`) need uEncrypt to unwrap. A
  plain age tool will decrypt them, but its output is the signed container,
  not the original content. To share a file with age users, encrypt without
  `-s` and send a detached `.sig` if needed.
- **Post-quantum and classic recipients cannot be mixed in one file.** age
  enforces this so that the file is not weakened to classic strength. Recipients
  using age tools older than v1.3 need a classic key (`keys new NAME --classic`).
- **Legacy RSA keys** can only decrypt. Re-encrypt old files with
  `uencrypt decrypt -o - old.enc | uencrypt encrypt -o new.age -`.

## Desktop app

`uencrypt-gui` uses the same keyring, file formats and checks as the CLI.
It has pages for Encrypt, Decrypt, Sign & Verify and Keys. You can drop files
onto the window or open a `.age` file with the app. Locked keys ask for their
passphrase when they are needed.

On Linux, the app and the CLI share a keyring (`~/.config/uencrypt`, or
`$UENCRYPT_KEYRING`). The Microsoft Store version keeps its keyring in the
app's own private storage, so it does not share one with a separately
installed CLI. Copy keys between them with *Back up secret key…* and
*Import…* on the Keys page.

## Install

- **Debian/Ubuntu:** install `uencrypt_<version>_<arch>.deb` for the CLI,
  which has no dependencies and suits servers. Add
  `uencrypt-gui_<version>_<arch>.deb` for the desktop app, which needs
  GTK 3 and WebKitGTK 4.1. Install them with
  `sudo apt install ./uencrypt_*.deb ./uencrypt-gui_*.deb`.
- **Windows:** the desktop app is distributed as an MSIX package through the
  Microsoft Store.

## Building

You need Go 1.27 or later. The desktop app also needs Node.js 20+ and the
[Wails](https://wails.io) v2 CLI
(`go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0`). On Linux, it
also needs `libgtk-3-dev` and `libwebkit2gtk-4.1-dev`.

```sh
go build -o bin/uencrypt ./cmd/uencrypt          # CLI
go test -tags webkit2_41 ./...
(cd gui && wails build -tags webkit2_41)         # desktop app: gui/build/bin/uencrypt-gui
(cd gui && wails dev -tags webkit2_41)           # desktop app with live reload
```

Packages:

```sh
packaging/build-deb.sh 1.2.3            # artifacts/deb/: CLI and GUI .deb for this machine
GOARCH=arm64 packaging/build-deb.sh 1.2.3 cli
```

```powershell
# Windows, with the Windows SDK installed. The identity values come from Partner Center.
./packaging/build-msix.ps1 -Version 1.2.3.0 -Architecture x64,arm64 `
    -IdentityName ... -Publisher "CN=..." -PublisherDisplayName "..."
./packaging/build-msix.ps1 -SelfSign    # local sideload test
```

Each package includes `THIRD-PARTY-NOTICES.txt`, which is generated by
`go run ./tools/notices`.

### Releases

GitHub Actions ([build.yml](.github/workflows/build.yml)) runs the tests and
builds the `.deb` packages (amd64 and arm64) and the MSIX packages (x64 and
arm64) on every push. Pushing a tag `vX.Y.Z` also publishes a GitHub release
with those packages attached. For Store builds, set the repository variables
`MSIX_IDENTITY_NAME`, `MSIX_PUBLISHER` and `MSIX_PUBLISHER_DISPLAY_NAME` to
the values from Partner Center (Product management → Product identity).

## Licence

MIT. See [LICENSE](LICENSE).
