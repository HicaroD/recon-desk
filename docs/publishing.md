# Publishing ReconDesk

GitHub Actions submits stable GitHub releases to the public Firefox Add-ons (AMO) listing. Mozilla controls validation, signing, review, and availability.

## One-time setup

1. Choose a permanent `browser_specific_settings.gecko.id` in `extension/manifest.json`. The current `client-watcher@local.invalid` is a development ID and the publish workflow rejects it. Keep the permanent ID for every subsequent release.
2. Update any development-ID references in the Firefox browser tests when changing the ID. Export existing research before switching IDs: Firefox treats the new identity as a separate extension.
3. Choose a license, prepare privacy and permission explanations, and create the first listing through the [Mozilla Developer Hub](https://addons.mozilla.org/developers/). Choose **On this site** for public distribution. Complete the description, screenshots, support information, and reviewer instructions.
4. Generate credentials on [Mozilla's API credentials page](https://addons.mozilla.org/developers/addon/api/key/).
5. In this GitHub repository, open **Settings → Secrets and variables → Actions → New repository secret** and add:
   - `AMO_JWT_ISSUER`: Mozilla's JWT issuer/API key.
   - `AMO_JWT_SECRET`: Mozilla's JWT secret/API secret.

The workflow needs an existing AMO listing under that ID, accessible to the credential owner. It does not create listing copy, choose a license, or upload screenshots. After submitting the initial version manually, use a higher version for the first automated submission.

## Release a version

1. Set the same new version in `extension/manifest.json` and `package.json`, and update the root package version in `package-lock.json` (for example, run `npm install --package-lock-only` after editing the versions).
2. Run:

   ```sh
   npm ci
   npm run check
   npm run lint:extension
   npm run check:release -- v0.1.1
   ```

   Replace `v0.1.1` with the intended tag. The release check requires an exact `v<manifest version>` match, matching package version, and a non-development add-on ID.
3. Run the existing Firefox browser tests documented in the README. CI currently runs Node tests, JavaScript syntax checks, and extension lint; it does not run the Selenium browser suites.
4. Merge the release changes into `master` and confirm CI succeeds.
5. Create and publish a GitHub release with the matching tag, targeting that commit. Draft releases do not trigger submission. Releases marked as prereleases run checks but skip AMO submission.
6. Watch **Actions → Submit to Firefox Add-ons** and monitor Mozilla's developer dashboard/email for review messages.

The workflow checks the release, builds the extension, saves an **unsigned ZIP** as a workflow artifact, and submits a listed version using `web-ext sign`. Credentials are exposed only to the steps that need them. Submissions are serialized to avoid overlapping release uploads.

`--approval-timeout 0` stops waiting after submission. A green workflow means AMO accepted the submission, not that review finished or the version is public. No signed XPI is downloaded or attached to the GitHub release. AMO distributes the signed extension and handles updates for AMO installations.

## Failed submissions

Read the failed step and check the AMO dashboard before rerunning. An interrupted job may already have submitted the version; blindly retrying can fail because that version exists. Resolve review issues through the Developer Hub, or prepare a higher version when needed. A failure in the final summary step does not undo a successful submission.

## Tooling and source

`web-ext` is pinned in `package.json` and `package-lock.json`; workflows use `npm ci`. Update and verify the tooling through a normal pull request.

The build packages `extension/` only. Repository tests, Node dependencies, fixtures, and GitHub credentials are not included. The current extension ships readable JavaScript without a compilation step. If bundling or minification is introduced, revisit [Mozilla's source-submission requirements](https://extensionworkshop.com/documentation/publish/source-code-submission/) and configure a source archive for reviewers.

See [Mozilla's submission guide](https://extensionworkshop.com/documentation/publish/submitting-an-add-on/) for the listing and review process.
