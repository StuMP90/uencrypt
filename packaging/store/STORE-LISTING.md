# Microsoft Store listing

Text and answers for the uEncrypt submission in Partner Center, ready to paste in. Limits in
brackets are Partner Center's. The screenshots, the cover image and the Store logos are all in
this folder.

## Product identity

| Field | Value |
|---|---|
| Product name | uEncrypt |
| Developed by / publisher display name | Stuart Millington (must match Partner Center) |
| Category | Security (subcategory: none) |
| Pricing | Free, no in-app purchases, no ads |
| Markets | All |
| Package | `uEncrypt_<version>_x64.msix` and `uEncrypt_<version>_arm64.msix` from the release workflow, built with the Partner Center identity values (README → Releases) |
| Minimum OS | Windows 10 version 1809 (build 17763) or later, x64 or Arm64 |

## Links

| Field | Value |
|---|---|
| Privacy policy URL | <https://github.com/StuMP90/uencrypt/blob/master/PRIVACY.md> |
| Website | <https://github.com/StuMP90/uencrypt> |
| Support contact | <https://github.com/StuMP90/uencrypt/issues> |

uEncrypt doesn't collect or send anything, but Partner Center asks for a privacy policy URL for
most full-trust desktop apps. The app also holds people's secret keys and opens their private
files, so a short policy saying what happens to them avoids certification questions. It must be
live at that URL, so push `PRIVACY.md` to `master` before submitting.

## Short description [1,000 characters]

> uEncrypt is a free, simple app to encrypt, decrypt and sign files. New keys are post-quantum
> (ML-KEM-768 + X25519), so files stay safe even against future quantum computers. Encrypt for
> yourself, for the people you work with, or with just a passphrase. Files use the open age
> format, so they aren't locked into one app. Nothing leaves your computer: no accounts, no
> cloud, no telemetry.

## Description [10,000 characters]

> uEncrypt encrypts, decrypts and signs files on your own computer. Drop files onto the window,
> tick who should be able to open them, and press Encrypt. That's all there is to it.
>
> **POST-QUANTUM BY DEFAULT**
>
> New keys combine ML-KEM-768, the post-quantum standard, with the well-proven X25519. A file
> stays safe unless both are broken, so anything you encrypt today is protected against
> "harvest now, decrypt later" attacks by future quantum computers.
>
> **ENCRYPT FOR THE RIGHT PEOPLE**
>
> Encrypt a file for yourself, for any number of contacts at once, or with a passphrase. Each
> person opens it with their own key, so nobody has to share a password. Share your contact card
> (your public key) by copying it or saving it to a file, and import other people's the same
> way. You can also encrypt to an existing SSH public key (ssh-ed25519 or ssh-rsa) and decrypt
> with your SSH private key.
>
> **SIGN AND VERIFY**
>
> Sign files to prove they came from you and haven't been changed, either as a separate .sig
> file or inside the encrypted file. Signatures are hybrid too (ML-DSA-65 + Ed25519). When
> decrypting, you can require a signature from a particular person, and a file that isn't signed
> by them is refused.
>
> **OPEN, STANDARD FORMAT**
>
> Encrypted files are ordinary age files (.age), an open, widely reviewed format. Unsigned files
> can be opened by any age v1.3 tool, such as age or rage, on Windows, macOS or Linux. Double-click
> a .age file to open it in uEncrypt.
>
> **SEE WHAT'S INSIDE**
>
> Click ⓘ next to any file to see what it is: who it's encrypted for, whether it's post-quantum,
> whether one of your keys can open it, and its size. "Look inside…" decrypts it in memory to list
> the contents of zip and tar archives and show who signed it, without saving anything.
>
> **SAFE BY DESIGN**
>
> Output is written under a temporary name and only renamed once the file has been fully
> decrypted and any required signature checked, so a failed or tampered file never leaves a
> half-written result behind. Keys can have a passphrase, which is asked for only when it's
> needed. Existing files are never replaced without asking.
>
> **PRIVATE**
>
> uEncrypt works entirely offline. It has no accounts, cloud, analytics, telemetry, advertising
> or update checks, and never connects to the internet. Your keys and files stay on your computer.
>
> **OLD FILES STILL WORK**
>
> Import RSA keys from the older ppkencrypt tools to decrypt their .enc files, in both the
> original and chunked formats.
>
> **A COMMAND LINE TOOL TOO**
>
> A matching uencrypt command line tool, for scripts, servers and unattended backups, is
> available for Linux from GitHub, and reads and writes the same files.
>
> uEncrypt is open source under the MIT licence: <https://github.com/StuMP90/uencrypt>

## What's new in this version [1,500 characters]

For the first submission:

> First Microsoft Store release.

## Product features [up to 20, 200 characters each]

1. Encrypt and decrypt files with post-quantum keys (ML-KEM-768 + X25519)
2. Encrypt for several people at once; each opens the file with their own key
3. Encrypt with a passphrase when the other person has no key
4. Sign files and verify signatures, with hybrid ML-DSA-65 + Ed25519 signatures
5. Require a signature from a particular person when decrypting
6. Open, standard age format, readable by other age tools
7. Encrypt to SSH public keys and decrypt with your SSH private key
8. Inspect any file: who it's for, whether it's post-quantum, and what's inside
9. Drag and drop files, or double-click a .age file to open it
10. Optional passphrase on each key, asked for only when needed
11. Never leaves a half-written file behind if decryption or a signature check fails
12. Share and import contact cards by copy and paste or by file
13. Decrypts old ppkencrypt .enc files with imported RSA keys
14. Works entirely offline, with no accounts, cloud or telemetry

## Search terms [up to 7, 30 characters each, 21 words in total]

1. file encryption
2. encrypt files
3. post-quantum
4. age encryption
5. digital signature
6. decrypt
7. public key

That's 12 words.

## Copyright and trademark info [200 characters]

> © 2026 Stuart Millington. Open source under the MIT licence; see LICENSE.

## Additional licence terms

Leave this empty to use the standard Microsoft application licence terms. The app's own MIT licence
and the third-party notices ship inside the package (`LICENSE`, `THIRD-PARTY-NOTICES.txt`).

## Screenshots [up to 10; PNG; 1366×768 or larger; captions 200 characters]

All are 1920×1080. They were taken from the real app running against a throwaway keyring with
made-up contacts (alice, jordan, sam, nightly-backups) and made-up files. No real keys or data
appear in them.

| File | Caption |
|---|---|
| `Screenshot-1-encrypt.png` | Encrypt files for several people at once, and sign them as you |
| `Screenshot-2-decrypt.png` | Decrypt in one go, with each file's signature checked |
| `Screenshot-3-inspect.png` | See who a file is for, whether it's post-quantum, and what's inside |
| `Screenshot-4-sign.png` | Sign files and verify signatures |
| `Screenshot-5-keys.png` | Manage your keys and contacts; post-quantum by default |
| `Screenshot-6-unlock.png` | Keys can have a passphrase, asked for only when needed |

Use Screenshot-1 first; the Store shows the screenshots in the order they're uploaded.

The screenshots were rendered on Linux, so the theme matches Windows but the typeface may differ
slightly. The keyring path on the Keys page was changed to the Windows default
(`C:\Users\Alex\AppData\Roaming\uencrypt`) so it doesn't show a Linux path.

To regenerate them after UI changes, run `wails dev` with `UENCRYPT_KEYRING` set to a throwaway
folder, add a few contacts and sample files, and capture the frontend at `localhost:34115` with
headless Chrome at 1280×720 and device scale 1.5.

## Store artwork

| File | Partner Center field |
|---|---|
| `SuperHeroArt-1920x1080.png` | Store listing → Promotional images → 16:9 Super hero art (1920×1080). It has no text: the Store overlays the app name in the lower left, so that corner is left empty. |
| `StoreLogo-300x300.png` | Store listing → Store logos (required), plus the 150 and 71 sizes |

The tile and taskbar icons the OS uses are inside the package already
([`../msix/Images/`](../msix/Images/)), separate from these.

## Additional system requirements

| | Minimum |
|---|---|
| Memory | 2 GB |
| Disk | 50 MB, plus space for your encrypted files |

## Product declarations

| Declaration | Answer |
|---|---|
| This app allows users to make purchases, but does not use the Microsoft Store commerce system | No |
| This app has been tested to meet accessibility guidelines | No; it hasn't been formally tested |
| Customers can install this app to alternate drives or removable storage | Yes |
| This app depends on non-Microsoft drivers or NT services | No |
| Windows can include this app's data in automatic backups to OneDrive | No. The keyring holds secret keys, which shouldn't be copied to the cloud without the user's choice. People back up their keys with *Back up secret key…* on the Keys page. |
| This app collects, stores or transmits personal information | No; see the privacy policy |

## Age rating (IARC questionnaire)

Choose the "Utility, productivity, communication or other" category, then answer:

- Violence, fear, sexuality, nudity, gambling, drugs, alcohol, tobacco, crude humour, bad
  language: **No**. The app contains no content of its own.
- Users can interact or exchange content with each other: **No**. The app never connects to the
  internet; people send encrypted files to each other by their own means.
- Shares the user's location: **No**.
- Digital purchases: **No**.
- Unrestricted internet access (a web browser or search): **No**.

The expected result is 3+ / Everyone.

## Capabilities and their justification

The package declares only one capability ([`AppxManifest.xml`](../msix/AppxManifest.xml)):

| Capability | Type | Why |
|---|---|---|
| `runFullTrust` | Restricted | uEncrypt is a Go + WebView2 (Wails) desktop Win32 app packaged as MSIX, not a UWP app. Every packaged desktop app needs this capability to run. |

Paste this into **Submission options → Restricted capabilities** for `runFullTrust`:

> uEncrypt is a desktop (Win32) application built with Wails (Go and WebView2) and packaged with
> MSIX. runFullTrust is required for any packaged desktop app to run. The app uses it to read the
> files the user chooses or drops onto the window, and write the encrypted, decrypted or signature
> files next to them or in a folder the user picks. It makes no network connections, does not
> install services or drivers, and does not change system settings.

**Not requested**, and why:

- **`broadFileSystemAccess`**. That's for UWP apps. A full-trust app already opens the files the
  user picks, drops or double-clicks with the user's own permissions.
- **`internetClient`**. The app never uses the network.

The package also registers the `.age` file type, so double-clicking a `.age` file opens it in
uEncrypt. That's a manifest extension, not a capability.

## Notes for certification

Paste into **Submission options → Notes for certification**:

> No account or sign-in is needed, and the app is free with no purchases. It works offline and
> makes no network connections.
>
> To test: on the **Keys** page, choose **New key**, give it a name, and leave the passphrase empty
> (or set one). Then on the **Encrypt** page, choose **Choose files…** or drop any file onto the
> window, tick the new key, and press **Encrypt**. A `.age` file appears next to the original. On
> the **Decrypt** page, add that `.age` file and press **Decrypt** to get the original back (it asks
> before replacing the original). **Sign & Verify** signs a file and checks the `.sig` file it makes. The ⓘ
> button next to any file shows what it is.
>
> The app's keys are stored in its own folder in the user's profile (the package's private
> AppData). Nothing is sent anywhere, and the app has no telemetry.

## Before each submission

- [ ] Build with the Partner Center identity values (repository variables `MSIX_IDENTITY_NAME`,
      `MSIX_PUBLISHER`, `MSIX_PUBLISHER_DISPLAY_NAME`).
- [ ] Check that `PRIVACY.md` on `master` is current. Update its date if what the app stores or
      reads has changed.
- [ ] Retake the screenshots if the UI has changed visibly.
- [ ] Fill in "What's new".
- [ ] Run the Windows App Certification Kit on the MSIX (optional; Partner Center runs its own).
