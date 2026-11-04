# Android security boundaries

This MVP requests no broad package inventory permission, Accessibility Service, VPN service, root access, or network permission.

## What it can inspect

- Files the user explicitly selects.
- APK package metadata exposed by Android's package parser.
- Hashes calculated locally from the selected file.

## What it cannot claim

- It cannot inspect private data or live memory belonging to other applications.
- It cannot guarantee detection of unknown, obfuscated, packed, or runtime-loaded malware.
- It does not continuously monitor every app or every network connection.
- It does not uninstall another application silently.
- It does not declare an APK safe merely because a few metadata checks return no warning.
- It does not replace Google Play Protect or a professionally validated antivirus engine.

## Remediation

The encrypted quarantine function stores a verified copy inside the app's private directory. The source remains where the user selected it; the app does not delete it automatically. The optional APK uninstall handoff asks Android to display its normal uninstall confirmation UI. System apps, device-owner policies, provider permissions, and Android-version differences may prevent a requested action.

## Future package visibility

A security app may have a legitimate use for QUERY_ALL_PACKAGES, but Google Play requires declaration and review. This MVP intentionally avoids requesting it until a documented need and Play policy review exist.
