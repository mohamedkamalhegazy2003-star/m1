# Quotation Management (Desktop) · إدارة عروض الأسعار

Windows desktop app built with Electron. Arabic / English (RTL), one server device + any number of terminals.

## Features
- **Arabic / English** interface (button at the bottom of the menu). Arabic typing is right-to-left automatically in every text field.
- **Server + terminal (طرفي)**: on first run each device chooses its mode.
  - *Server*: keeps all data in `data.json` (shown in Settings) and serves the app on the network (default port `3210`).
  - *Terminal*: enter the server's IP and port; works on the same data. Changes from other devices appear automatically.
  - Allow the app through Windows Firewall on the server device the first time it asks.
- **Import clients / products from Excel** (`.xlsx`, `.xls`, `.csv`): columns are detected automatically from Arabic or English headers (or from the cell contents when there is no header) and can be corrected before importing. Existing names are updated or skipped.
- **Edit** clients, products / services, users and company data (menu lists → *Edit*).
- **Quotation view** with company header, PDF export, print, and **WhatsApp**: the PDF is saved to `Documents/Quotations`, its folder opens, and WhatsApp opens a chat with the client's number and a ready message — attach the PDF there (WhatsApp links cannot attach files by themselves).

## Run locally
    npm install
    npm start

## Build installer locally
    npm run dist      # output: dist/*.exe

## Build on GitHub
Push a tag, e.g. `git tag v1.1.0 && git push origin v1.1.0`.
GitHub Actions builds the installer and attaches it to the Release.
You can also run it from Actions > Build Windows installer > Run workflow.
