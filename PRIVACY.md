# Privacy Policy

Last updated: 2026-10-25

This policy applies to uEncrypt, the desktop app and the `uencrypt` command line tool, whether
installed from the Microsoft Store, from a `.deb` package or from a release on GitHub.

## In short

uEncrypt collects nothing. It has no accounts, analytics, telemetry, advertising, crash reporting
or update checks, and it makes no network connections at all. Your keys and files never leave
your computer unless you send them somewhere yourself. The developer receives nothing from the
app.

## Your files

uEncrypt reads only the files you choose, drop onto the window or open with it, and writes only
the output you ask for: the encrypted, decrypted or signature file, or a key you export or back
up. Everything is done on your computer. "Look inside…" (and `inspect --contents`) decrypts a
file in memory to describe it and saves nothing.

## Data stored on your computer

uEncrypt keeps a keyring folder: `%APPDATA%\uencrypt` on Windows, `~/.config/uencrypt` on Linux,
or the folder set by `UENCRYPT_KEYRING`. The Microsoft Store version keeps it in the app's own
private storage, which Windows removes when the app is uninstalled. The keyring holds:

- **Your secret keys**, readable only by your user account. Each can be locked with a
  passphrase. Secret keys are never sent anywhere; they leave the keyring only when you export or
  back one up.
- **Your contact cards** (public keys) and **your contacts' contact cards**, under the names you
  give them.
- **Old RSA keys** you import to decrypt `.enc` files.
- **Which of your keys is the default.**

There is no other settings file, history, cache or log.

## SSH keys

To decrypt files encrypted to an SSH key, uEncrypt reads `~/.ssh/id_ed25519` and `~/.ssh/id_rsa`
(`.ssh` under your user profile on Windows), or another SSH key you point it at. They are read
only when needed, and never copied into the keyring or sent anywhere.

## Clipboard

uEncrypt writes to the clipboard only when you click to copy a contact card, and reads it only
when you paste into the app yourself.

## Children

uEncrypt is a general-purpose tool. It is not aimed at children and collects no data from
anyone.

## Third parties

When you install uEncrypt from the Microsoft Store, Microsoft handles the download, licensing and
updates under its own privacy statement: <https://privacy.microsoft.com/privacystatement>. The
links on the About page open in your web browser, and those websites' own policies apply.

## Changes

If this policy changes, the new version will be published at this address with a new date. The
full history of this file is kept in the repository.

## Contact

Questions about privacy can be raised as an issue at <https://github.com/StuMP90/uencrypt/issues>.
