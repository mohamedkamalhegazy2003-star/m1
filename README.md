# Quotation Management (Desktop)

Windows desktop app built with Electron.

## Run locally
    npm install
    npm start

## Build installer locally
    npm run dist      # output: dist/*.exe

## Build on GitHub
Push a tag, e.g. `git tag v1.0.0 && git push origin v1.0.0`.
GitHub Actions builds the installer and attaches it to the Release.
You can also run it from Actions > Build Windows installer > Run workflow.
