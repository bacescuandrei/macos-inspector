# PDF Inspector

PDF Inspector reviews a document before you open it. It is a built-in, dependency-free static triage module, not a viewer, sanitizer, antivirus engine, PDF conformance validator, or runtime sandbox. It does not wrap or require PDFiD or pdf-parser.

## Use it from the dashboard

1. Double-click **macOS Inspector.command** to start and authorize the local dashboard.
2. Choose **PDF Inspector** in the page navigation. This opens a separate page containing only document analysis and PDF history, not Mac audit controls or scan history.
3. Select a PDF up to 25 MiB. Selecting the file alone does not start analysis.
4. Press **Inspect PDF**. Do not open the original in a PDF reader just to inspect it here.
5. Review the assessment, declared triggers, JavaScript, destinations, attachments, and limitations.
6. Open the HTML or JSON report. **Recent PDF inspections** retains links to the latest 25 reports in the current output directory.

Use **Back to Mac audit** for application, process, and system investigations. The audit page links back to **PDF Inspector**. These are separate HTML documents with separate module scripts: `/` or `/index.html` for Mac audit, and `/pdf-inspector.html` for PDF analysis. Authorization carries across both pages in the same browser tab. Opening the PDF page does not load audit code, Mac application inventory, or audit history, and never starts a scan.

Saved reports remain available through **Recent PDF inspections** after navigating away and returning. An unsaved file selection or displayed result is not guaranteed to survive page navigation or refresh. **Clear** removes that selection and displayed evidence without deleting saved reports. If analysis is still running, the browser asks before leaving the page.

The PDF page adapts to narrow displays with labeled evidence rows instead of wide tables. Short entrance transitions and a busy indicator show interface changes without implying analysis progress. Reduced-motion preferences disable these effects.

The original PDF is read for this analysis and is not saved by Inspector. Reports are stored locally with owner-only permissions. Inspector does not delete or modify the original. Restarting the dashboard invalidates private HTTP report links; use the authorized history to obtain current links or open the saved HTML report locally.

## Prepare a sharing copy

After a new inspection, use **Preview sharing copy** below the analysis limitations. Review the summary and expand **All fields in this sharing copy** before downloading **sharing HTML** or **sharing JSON**. Both exports use the same reduced fields. Downloads use a generic filename, not the original document name. This workflow does not contact an external service or save another copy on the server.

The reduced copy retains the recorded assessment, supported structural-name counts, action-type counts, evidence-record counts, and scope caveats. It omits document and attachment names, metadata, source timestamps and inspection identifiers, destinations and file paths, JavaScript text/indicators/hashes, raw object context, raw diagnostics, and detailed document size/structure. Document SHA-256 is omitted by default. Select **Include document SHA-256** only if the recipient needs the exact fingerprint and you accept that it can identify the PDF.

This is not anonymization: counts and optional fingerprints can still identify a document. Detailed evidence needed for investigation is intentionally omitted, and the copy is not an authenticated original export. Missing indicators do not establish safety. No metadata is changed in the original report. Changing the selected PDF or hash option invalidates the preview and requires preparing another copy. Reports already in history retain their original private HTML/JSON links; inspect a document again to use this current-result workflow.

## What is inspected

| Evidence | Interpretation |
| --- | --- |
| PDF header, offset, final EOF marker, observed objects | Structural observations, not complete xref or conformance validation |
| Parsed names including escaped names such as `/Java#53cript` | Counts within inspected objects, not proof that a feature runs |
| `/JS` strings and supported referenced streams | Bounded JavaScript excerpts, hashes, and simple static API/string indicators |
| Catalog `/OpenAction`, `/AA`, `/A`, `/Next` and JavaScript name trees | Declared triggers, action chains, or document-level script registration |
| `/URI`, file/form targets and URL strings in JavaScript | Recorded destinations, never observed network requests |
| `/Filespec`, `/EF`, `/EmbeddedFile` | Attachment references and filenames; contents are not extracted or executed |
| Title, author, creator, producer and dates | Declared, unverified document metadata |

The parser supports ordinary object dictionaries, arrays, indirect references, literal/hexadecimal strings, escaped names, and compressed object streams. Stream decoding supports bounded Flate, ASCIIHex, and ASCII85 filter chains without decoding parameters. Other filters or predictor parameters affecting inspected script/object streams produce limitations. Image and page streams are not rendered or comprehensively decoded. Strings that merely mention `/JavaScript` are not treated as structural JavaScript entries.

All recovered revisions can contribute evidence. Cross-reference tables are not validated to establish the reader's final effective object graph. Repeated object identities and possible incremental updates therefore produce explicit limitations; an action recorded in an older revision may no longer be active.

An OpenAction entry outside a catalog is recorded with an unestablished trigger, not as a document-open action. The report retains the feature and an interpretation limit; this does not make a malformed entry harmless. Catalog detection still uses recovered structure rather than validated final cross-reference reachability.

## Practical examples

### An invoice contains an ordinary hyperlink

An annotation records `/S /URI` with a web address. The trigger is **Annotation or user interaction**, not **Document open**. Inspector did not contact the address. Confirm the sender and inspect the displayed destination; the presence of a link alone does not establish malware.

### A document contains JavaScript on opening

A catalog `/OpenAction` refers to an action with `/S /JavaScript` and a `/JS` string or stream. The report shows **Document open**, object context, and a bounded code excerpt. A recognized `app.launchURL` or `submitForm` expression is labeled as a possible URL/form interaction. This does not prove a request occurred or will occur in your reader. Keep the original closed while validating its source and purpose.

### A form submits data

An action records `/S /SubmitForm` and a destination. Review whether the action is attached to a document-open entry, additional event, annotation, or has an unresolved trigger. A legitimate form can submit data intentionally. Validate where information would be sent and whether that behavior is expected.

### A PDF has an attachment or launch action

Review the declared file target and trigger. A file reference is not proof the attachment is executable or malicious. Inspector neither extracts nor launches it. Preserve the original if you need separate artifact analysis.

### The report finds no supported active features

This means only that supported static features were not identified within the inspected scope. It does not rule out phishing content, hidden or unsupported structures, embedded-file threats, obfuscation, or PDF reader exploits. The malware verdict remains **Not determined**.

## Limits and privacy

- Encrypted content is not decrypted. No password collection or password cracking is provided.
- XFA, rich media, embedded document contents, executable attachments, and runtime JavaScript behavior are not comprehensively analyzed.
- Header and object recovery do not establish full PDF validity, digital-signature validity, document authenticity, or the final effective revision.
- The input is capped at 25 MiB, 5,000 objects, 250,000 syntax/traversal steps, bounded nesting, 4 MiB per decoded stream, and 32 MiB total decoded streams. Records and script previews are bounded. Upload read time, worker CPU, and wall-clock time are limited. Linux has an additional address-space cap; macOS does not have that hard memory cap.
- A stopped or failed worker produces an error, not a clean verdict. Retained partial evidence is accompanied by explicit limits.
- No code runs, no page is rendered, no attachment is executed, and no destination or reputation provider is contacted. The worker is a separate process, not a complete OS sandbox.
- Reports can contain a filename, SHA-256, author information, destinations, and script excerpts. Review them before sharing. The SHA-256 identifies the uploaded bytes; it does not sign or authenticate the report.

The module builds on PDF action concepts documented in the [Adobe PDF reference](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.5_v6.pdf). For related independent command-line tools, see Kali's [pdf-parser](https://www.kali.org/tools/pdf-parser/) documentation.
