# Citizenship Vocab Examples

This directory contains various examples and built files that are included in
the spec doc.

## Build Process

A script is used to read base credential files, sign them, and generate QR codes.

```
npm install
npm run build
```

- Edit the base files as needed.
- Commit the base and output files:
  - `*-signed.jsond`
  - `*-qrcode.html`
  - `*-info.html`
- Static data is used to minimize data changing when not needed.
