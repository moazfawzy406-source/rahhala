# Rahhala | رَحّالَة

Private backup of the real Arabic class-hub project, prepared 23 November 2026. This is the actual application source, not a generated replacement or placeholder project. No production deployment is performed by creating or downloading this repository.

## Contents and version boundary

- `src/index.js`: server/API source from the deployed navy/gold glass and security release of 22 November 2026.
- `public/`: real application interface, institution asset, PWA manifest, icons and service worker. Includes all four themes, username-based login, resources, chat, members, account, administration and study meeting UI.
- `schema.sql`: complete empty database schema assembled from the application's table requirements. Contains no production users or chat records.
- `data/study-content.json` and `.sql`: actual catalog read from the application on 23 November 2026: 7 subjects, 21 sections and 9 educational links, preserving identifiers, order, titles and destinations. Creator identity fields are excluded. Telegram links may require membership of the original class groups; this repository does not grant that membership or contain the linked files.
- `wrangler.jsonc`: actual non-secret application/DB binding configuration. The existing binding identifier is retained to preserve real project configuration. It is not an access credential. Do not run production commands casually against it.
- `tests/`: isolated synthetic-data security tests and tiny synthetic fixtures. Test credentials/keys inside tests are deliberately fake and never used in production.
- `pending-download-fix/`: the prepared, locally tested download repair as three source patches. It has NOT been applied to this baseline and has NOT been deployed. Keeping it separate avoids presenting an unpublished patch as the production source.

## Product features

Arabic RTL mobile-first class hub with Cairo typography, dark navy/gold glass styling and dark/light/sepia/warm-night themes. Username/password registration requires admin approval. Member, admin and protected owner roles. Subject/section resource organization with editing, movement and ordering. Announcements, questions and general chat with text, image/file uploads, voice recordings, replies, reactions, editing, hide/delete, read/delivery receipts and separately approved historical access. Members and media gallery, public profiles, private administrative recovery, session management with two-hour inactivity expiry, and a configurable browser-based study meeting.

The code preserves existing behavior, including limitations. A backup is not a claim that every security or usability edge case has been solved. Review authorization, rate limits, media/history gates, storage cleanup and real-device behavior before using a new installation.

## Local development

Use a supported Node.js LTS release and the pinned package lock:

```sh
npm ci
npm test
npm run check
```

`npm test` runs only against a temporary local database with synthetic identities and files. `npm run check` performs a build/dry run, not a deployment. Neither command should be changed to target the live database.

For a separate local development database, initialize the empty schema and catalog with local-only commands:

```sh
npx wrangler d1 execute halqa-db --local --file schema.sql
npx wrangler d1 execute halqa-db --local --file data/study-content.sql
npm run dev
```

Do not substitute a remote flag. No user is pre-created and no default password is supplied. New registration remains pending until an owner/admin is initialized through a separate authorized setup. Configure locally generated signing material privately through a local ignored configuration file, following the variable names referenced in the code. No secret values are included here.

The supplied root schema is for a NEW empty local database. It is not a migration to run over production. The catalog inserts are intended for an empty local database too.

## Private configuration and access

The source references protected file-signing and optional email-provider configuration by variable name only. No values are included. Email self-service recovery remains hidden/disabled in the UI; administrative temporary-password recovery is the current flow. The original non-secret study-meeting provider/room configuration remains in the real interface code. The existing non-secret DB binding configuration remains in the project config. These settings are included for fidelity, not as permission to operate any service.

Owner-only application archive access remains in the server implementation, but no source ZIP is put in the public assets folder. Do not add a publicly served source archive.

## Deliberately excluded

- All real user/account rows, names, email addresses, usernames, bios, avatars and personal profiles from the application database.
- Passwords and password hashes; active or expired sessions; session identifiers; password-reset records; authentication-attempt data.
- Chat messages, receipts/read state, reactions, hidden-message records, typing state, history requests and member activity.
- Private uploaded files, image/audio chunks and asset metadata; no underlying Telegram/Drive file bytes are copied.
- API keys, signing secrets, deployment credentials, vault items, cookies and environment files.
- Local runtime caches/state, dependency directories, build output, logs, deployment history and account caches.
- Prior source ZIPs and review screenshots/logs containing live context.
- The disabled recovery sender mailbox identity from configuration; it is not required for the current app behavior.
- Resource creator identity metadata, while retaining the educational content itself.

Actual app names, subjects, sections, educational resource URLs, branding assets, theme settings and non-secret runtime/binding configuration are intentionally retained. This repository must remain PRIVATE. Do not publish it or grant collaborators access without a separate decision from the owner.

## Testing and limits

The isolated security suite is retained with synthetic data. Download-fix tests were run separately before packaging its patches; those results do not mean the patch is live. Real-device camera/microphone, keyboard positioning, meeting-provider availability and production-scale behavior require separate verification. No live database export or restoration test is claimed.
