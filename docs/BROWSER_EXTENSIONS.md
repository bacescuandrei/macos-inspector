# Browser extension permissions

The browser audit explains permission declarations. It does not determine whether an extension is malicious, authenticate its publisher, verify store signatures, or establish which permissions the browser currently grants.

## Use the dashboard

1. Run **Privacy and browsers**, the browser-oriented investigation goal, or select **Browser artifacts** in Analyst view.
2. Open **Browser extension permissions** in the recorded scan. The panel is available in Simple and Analyst views.
3. Review the extension name, ID, observed version, browser profile, and permission explanations.
4. Distinguish **Declared requirement** from **Optional declaration**. Optional requests are not confirmed grants.
5. Open **Declared permission details and limits** for API names, site patterns, content-script matches and restrictions, and missing evidence.
6. Open the browser's own extension settings to confirm enabled state, actual site access, and granted permissions. Inspector does not disable or remove extensions.

Full scan HTML reports and investigation summaries contain the same permission explanations. Other evidence exports retain the structured permission data in the original findings. These reports may reveal internal host patterns, profile names, extension IDs, and sensitive local paths; review them before sharing. PDF sharing summaries do not redact Mac audit reports.

## Supported evidence

- Chrome, Brave, Edge, and Chromium: read `manifest.json` from the highest numeric version directory in the bounded local selection. Numeric selection avoids confusing `1.9` with `1.10`; it does not identify the enabled or active version. Multiple directories can remain after an update. Record a manifest SHA-256 without executing extension code.
- Manifest V2: separate API names and host patterns declared in `permissions` and `optional_permissions`.
- Manifest V3: also inspect `host_permissions`, `optional_host_permissions`, and content-script matches. Preserve exclusion matches, include-globs, and exclude-globs separately. Summaries aggregate declarations across scripts; they do not reconstruct each script's effective scope.
- Firefox: read bounded `extensions.json` addon metadata, including recorded `userPermissions`, `optionalPermissions` when available, and the `active` boolean. These are recorded requirements and state, not a fresh browser-runtime query or dynamic grant inventory. Missing optional metadata remains unavailable.
- Safari: retain a limited legacy-folder inventory and explicitly state that Safari app/WebExtension permissions and the complete extension inventory were not assessed. Do not parse Safari folders as Chromium manifests.

Unpacked, externally located, managed, built-in, or otherwise unobserved extensions may be missing from this inventory. Local manifest names, IDs, versions, and Firefox metadata are unverified declarations. Localized `__MSG_...__` names are not resolved, and no browser store is contacted.

## Interpret common observations

- Broad site patterns are a scope concern, not a malware verdict. Ad blockers, password managers, and other legitimate extensions can request wide access. Browser restrictions, excluded pages, and user choices can limit effective access.
- Cookie API requests do not by themselves establish access to every site's cookies. Review the corresponding site permissions in the browser.
- `activeTab` is temporary, user-action-dependent access, not a persistent declaration for all websites.
- `nativeMessaging` requests communication with a separate native host. Inspector does not establish that the host is installed, verify it, or execute it.
- Clipboard, history, downloads, tabs, scripting, request, proxy, management, and debugger explanations describe requested capabilities. No use of those capabilities was observed by this manifest inspection.
- **Permission analysis limited** means the source was missing, malformed, unsupported, or bounded. An empty permission list in a limited record is not evidence of no access.

Extension presence retains low review priority. Broad or optional requests do not independently increase severity or trigger process termination. No online reputation verdict or software allowlist is used.

## Bounds and failure behavior

Inspect at most 100 extension records, 20 version directories per extension, and 500 enumerated entries per directory. A Chromium manifest is limited to 512 KiB; Firefox addon metadata to 4 MiB. Permission lists and aggregated content-script scope lists retain at most 100 entries, each no longer than 512 characters. Normalized evidence is capped at 64 KiB per record and 1 MiB per profile. A size limit can omit declarations or later records; the limitation is recorded, not treated as a clean result.

Explicit symlinked extension directories, entries, manifests, and Firefox metadata are not followed. This is a read-only collection safeguard, not an OS sandbox or a defense against a compromised same-user account. Profile visibility still depends on filesystem permissions and the selected user. Collection notes propagate to scan coverage; the dashboard displays the first 60 collected records and identifies when more remain in raw findings.

The tests use fictional profiles and manifests. They exercise required/optional separation, numeric versions, unsupported schemas, malformed/null values, symlinks, file/list/output bounds, partial reads, escaping, both dashboard views, narrow widths, accessibility, and HTML export integration. They do not establish compatibility with every browser version or real-world malware detection accuracy.

## References

- [Chrome permission declarations](https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions)
- [Mozilla WebExtension permissions](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/permissions)
- [Firefox addon update permission metadata](https://searchfox.org/firefox-main/source/toolkit/mozapps/extensions/internal/XPIProvider.sys.mjs)
