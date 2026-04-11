# Light flipper
Light flipper application for C5 Board.

## Build
This repo contains one Flipper external app in the repository root (`application.fam`).

GitHub Actions workflows:
- `.github/workflows/build-fap.yml`
- `.github/workflows/release-fap.yml`
- `.github/workflows/deploy-docs.yml`

The workflow builds the app against the SDK versions currently used in this repo:
- `flipper-z-f7-sdk-mntm-dev-22408e4c.zip`
- `flipper-z-f7-sdk-unlshd-086.zip`

CI downloads those SDK archives directly, so the local `sdk/` folder does not need to be committed.

## Release
`release-fap.yml` reads `appid`, `fap_category` and `fap_version` from `application.fam`.

For `fap_version="0.0.1"` it creates release tag `v0.0.1` and uploads:
- `c5lab_dev_v0.0.1_momentum_dev.fap`
- `c5lab_dev_v0.0.1_unleashed.fap`

If the tag already exists, the release workflow skips publishing.

## Web uploader
The browser uploader lives in `docs/flipper_fap.html`.

It fetches the latest release asset from this repository and uploads it to Flipper over WebSerial.
Default install path:
- `/ext/apps/GPIO/c5lab_dev.fap`

After enabling GitHub Pages, the page will be available from:
- `https://c5lab.github.io/flipperLight/`

Local build example:
```sh
ufbt update -t f7 -l sdk/flipper-z-f7-sdk-mntm-dev-22408e4c.zip
ufbt faps
```
