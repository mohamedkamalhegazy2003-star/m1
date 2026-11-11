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

## Login and users
- On the **server device**, the first launch asks you to create the administrator account (this can only be done on the server device itself).
- Every device then signs in with a username and password. Passwords are stored hashed on the server only; 5 wrong attempts lock that username/device for a short time.
- Roles: **Admin** (everything, including users), **Sales** (all data), **Viewer** (read only). Admins add, edit, reset passwords and delete users from *Users*; everyone can change their own password in *Settings*.
- Note: traffic between devices is plain HTTP on your local network. Use it on a trusted network.

## Tabs
Open several quotations at once, like browser tabs: **+** or *Create Quotation* opens a new tab with its own draft; opening a quotation opens/focuses its tab. Drafts are kept (and restored after restarting) until you close the tab.

## Quotation templates (Settings)
Four black-and-white A4 templates (classic, formal double, simple, compact). Choose the default, duplicate a template, or edit its design (header, table style, fonts, margins, terms, signature/stamp boxes, footer) with a live preview. Print, PDF and WhatsApp use the template chosen on the quotation page.

## Run locally
    npm install
    npm start

## Build installer locally
    npm run dist      # output: dist/*.exe

## Build on GitHub
Push a tag, e.g. `git tag v1.1.0 && git push origin v1.1.0`.
GitHub Actions builds the installer and attaches it to the Release.
You can also run it from Actions > Build Windows installer > Run workflow.

## v1.3.0
- Starts with Windows in the background (tray icon: open / copy address / exit); toggle in Settings.
- Admin menu: users with granular permissions (create/edit/delete quotations, clients, products, requests, company, settings & templates), disable accounts, **login activity** (IP, device, sign-in/out, active devices with force sign-out).
- Open `http://<server-ip>:3210` from any device on the network for the full interface (Excel import, print/PDF via browser, WhatsApp link). Allow the app in Windows Firewall on the server device.
- Templates: company logo (auto black & white, width/position), extra text fields, header fields, size boxes.
- Select and delete quotations; numbering starts at 1000 (configurable prefix/start in Settings).
