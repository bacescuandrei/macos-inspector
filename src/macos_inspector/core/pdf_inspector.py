"""Bounded, static PDF triage. Never render, execute, or fetch document content."""
from __future__ import annotations

import base64
import hashlib
import json
from itertools import islice
import re
import subprocess
import sys
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from macos_inspector import __version__

MAX_PDF_BYTES = 25 * 1024 * 1024
MAX_OBJECTS = 5000
MAX_TOKENS = 250000
MAX_DECODED_STREAM = 4 * 1024 * 1024
MAX_DECODED_TOTAL = 32 * 1024 * 1024
MAX_RECORDS = 200
WORKER_TIMEOUT = 20
LIMITATION = "Static triage is not a safety verdict. No code was executed, no pages were rendered, and no destinations were contacted. Reader behavior, permissions, exploits, and obfuscated code cannot be determined by this analysis."
SPACE = b"\x00\t\n\x0c\r "
DELIMITERS = SPACE + b"()<>[]{}/%"
OBJECT = re.compile(rb"(?<![\w])([0-9]{1,10})\s+([0-9]{1,5})\s+obj\b")
TRAILER = re.compile(rb"(?<![\w])trailer\s*(?=<<)")
URL = re.compile(r"(?:https?|ftp)://[^\s<>\"'()\\]{1,2048}", re.I)
INTERESTING_NAMES = ("JavaScript", "JS", "OpenAction", "AA", "URI", "Launch", "SubmitForm", "GoToR", "GoToE", "EmbeddedFile", "Filespec", "RichMedia", "XFA", "AcroForm", "ObjStm", "Encrypt")
EVENT_LABELS = {"O": "Page open", "C": "Page close", "K": "Field keystroke", "F": "Field formatting", "V": "Field validation", "Fo": "Focus", "Bl": "Blur", "D": "Mouse press", "U": "Mouse release", "E": "Mouse enter", "X": "Mouse exit", "PO": "Page open", "PV": "Page visible", "PI": "Page invisible", "WC": "Document close", "WS": "Before save", "DS": "After save", "WP": "Before print", "DP": "After print"}


@dataclass(frozen=True)
class Name:
    value: str


@dataclass(frozen=True)
class Ref:
    number: int
    generation: int


class ParseLimit(ValueError):
    pass


class Limitations(list):
    """Bound diagnostic growth even when every recovered object is malformed."""
    def append(self, value):
        value = str(value)[:600]
        if value not in self and len(self) < 99:
            super().append(value)
        elif len(self) == 99:
            super().append("Additional analysis limitations omitted because the diagnostic limit was reached.")


class Syntax:
    def __init__(self, data: bytes, limitations: list[str]) -> None:
        self.data, self.pos, self.tokens = data, 0, 0
        self.limitations = limitations

    def skip(self) -> None:
        while self.pos < len(self.data):
            if self.data[self.pos] in SPACE:
                self.pos += 1
            elif self.data[self.pos:self.pos + 1] == b"%":
                end = self.data.find(b"\n", self.pos)
                cr = self.data.find(b"\r", self.pos)
                self.pos = min([v for v in (end, cr, len(self.data)) if v >= 0])
            else:
                break

    def word(self) -> bytes:
        self.skip()
        start = self.pos
        while self.pos < len(self.data) and self.data[self.pos] not in DELIMITERS:
            self.pos += 1
        return self.data[start:self.pos]

    def value(self, depth: int = 0):
        self.tokens += 1
        if depth > 40 or self.tokens > MAX_TOKENS:
            raise ParseLimit("Object nesting or token limit reached.")
        self.skip()
        data, start = self.data, self.pos
        if start >= len(data):
            raise ValueError("Unexpected end of object.")
        if data[start:start + 2] == b"<<":
            self.pos += 2
            result = {}
            while True:
                self.skip()
                if data[self.pos:self.pos + 2] == b">>":
                    self.pos += 2
                    return result
                key = self.value(depth + 1)
                if not isinstance(key, Name):
                    raise ValueError("Dictionary key is not a PDF name.")
                item = self.value(depth + 1)
                if key.value in result:
                    self.limitations.append("Duplicate dictionary keys were found; interpretation may differ between readers.")
                result[key.value] = item
        if data[start:start + 1] == b"[":
            self.pos += 1
            result = []
            while True:
                self.skip()
                if data[self.pos:self.pos + 1] == b"]":
                    self.pos += 1
                    return result
                result.append(self.value(depth + 1))
        if data[start:start + 1] == b"/":
            self.pos += 1
            end = self.pos
            while end < len(data) and data[end] not in DELIMITERS:
                end += 1
            raw = data[self.pos:end]
            self.pos = end
            raw = re.sub(rb"#([0-9a-fA-F]{2})", lambda m: bytes([int(m[1], 16)]), raw)
            return Name(raw.decode("latin-1"))
        if data[start:start + 1] == b"(":
            self.pos += 1
            nesting, result = 1, bytearray()
            while self.pos < len(data):
                char = data[self.pos]
                self.pos += 1
                if char == 92:
                    if self.pos >= len(data):
                        break
                    char = data[self.pos]
                    self.pos += 1
                    if char in (10, 13):
                        if char == 13 and data[self.pos:self.pos + 1] == b"\n":
                            self.pos += 1
                        continue
                    if 48 <= char <= 55:
                        digits = bytes([char])
                        for _ in range(2):
                            if self.pos < len(data) and 48 <= data[self.pos] <= 55:
                                digits += data[self.pos:self.pos + 1]
                                self.pos += 1
                            else:
                                break
                        result.append(int(digits, 8) & 255)
                    else:
                        result.append({110: 10, 114: 13, 116: 9, 98: 8, 102: 12}.get(char, char))
                elif char == 40:
                    nesting += 1
                    if nesting > 40:
                        raise ParseLimit("String nesting limit reached.")
                    result.append(char)
                elif char == 41:
                    nesting -= 1
                    if nesting == 0:
                        return bytes(result)
                    result.append(char)
                else:
                    result.append(char)
            raise ValueError("Unterminated PDF string.")
        if data[start:start + 1] == b"<":
            end = data.find(b">", start + 1)
            if end < 0:
                raise ValueError("Unterminated hexadecimal string.")
            raw = re.sub(rb"\s", b"", data[start + 1:end])
            self.pos = end + 1
            if len(raw) % 2:
                raw += b"0"
            return bytes.fromhex(raw.decode("ascii"))
        word = self.word()
        if not word:
            raise ValueError("Unexpected delimiter.")
        if re.fullmatch(rb"[+-]?\d+", word):
            number = int(word)
            checkpoint = self.pos
            second = self.word()
            if re.fullmatch(rb"\d{1,5}", second) and self.word() == b"R":
                return Ref(number, int(second))
            self.pos = checkpoint
            return number
        if re.fullmatch(rb"[+-]?(?:\d+\.\d*|\.\d+)", word):
            return float(word)
        if word == b"null":
            return None
        if word in (b"true", b"false"):
            return word == b"true"
        raise ValueError("Unrecognized object token.")


def _text(value) -> str:
    if isinstance(value, Name):
        return value.value
    if isinstance(value, bytes):
        if value.startswith((b"\xfe\xff", b"\xff\xfe")):
            return value.decode("utf-16", errors="replace")
        return value.decode("utf-8", errors="replace")
    return str(value) if value is not None else ""


class Inspector:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.limitations: list[str] = Limitations()
        self.objects: dict[tuple[int, int], dict] = {}
        self.records: list[dict] = []
        self.trailers: list[dict] = []
        self.name_counts = {name: 0 for name in INTERESTING_NAMES}
        self.decoded_total = 0
        self.decoded_cache: dict[tuple[int, int], bytes | None] = {}
        self.scripts: list[dict] = []
        self.destinations: list[dict] = []
        self.attachments: list[dict] = []
        self.actions: list[dict] = []
        self.metadata: dict[str, str] = {}
        self.resolving: set[tuple[int, int]] = set()
        self.walked = 0

    def resolve(self, value, depth: int = 0):
        if not isinstance(value, Ref):
            return value
        if depth > 30:
            self.limitations.append("Indirect reference depth limit reached.")
            return None
        key = (value.number, value.generation)
        if key in self.resolving:
            self.limitations.append("Cyclic indirect reference encountered.")
            return None
        obj = self.objects.get(key)
        if not obj:
            self.limitations.append(f"Unresolved reference {value.number} {value.generation} R.")
            return None
        self.resolving.add(key)
        try:
            return self.resolve(obj["value"], depth + 1)
        finally:
            self.resolving.discard(key)

    def decode(self, obj: dict) -> bytes | None:
        key = obj["key"]
        if key in self.decoded_cache:
            return self.decoded_cache[key]
        self.decoded_cache[key] = None
        raw = obj.get("stream")
        if raw is None:
            return None
        value = obj["value"]
        filters = self.resolve(value.get("Filter")) if isinstance(value, dict) else None
        filters = filters if isinstance(filters, list) else ([] if filters is None else [filters])
        try:
            if isinstance(value, dict) and value.get("DecodeParms") is not None:
                raise ValueError("Stream decoding parameters are not supported")
            if len(raw) > MAX_DECODED_STREAM:
                raise ValueError("Stream exceeds the per-stream limit")
            for algorithm in filters:
                name = _text(self.resolve(algorithm))
                if name in {"FlateDecode", "Fl"}:
                    decoder = zlib.decompressobj()
                    raw = decoder.decompress(raw, MAX_DECODED_STREAM + 1)
                    if len(raw) > MAX_DECODED_STREAM or not decoder.eof or decoder.unconsumed_tail:
                        raise ValueError("Flate stream is truncated or exceeds the decoding limit")
                elif name in {"ASCIIHexDecode", "AHx"}:
                    raw = re.sub(rb"\s", b"", raw).split(b">", 1)[0]
                    raw = bytes.fromhex((raw + (b"0" if len(raw) % 2 else b"")).decode("ascii"))
                elif name in {"ASCII85Decode", "A85"}:
                    raw = raw.strip()
                    if raw.startswith(b"<~"):
                        raw = raw[2:]
                    if not raw.endswith(b"~>"):
                        raise ValueError("ASCII85 terminator missing")
                    raw = base64.a85decode(raw[:-2], adobe=False)
                else:
                    raise ValueError(f"Unsupported stream filter: {name[:80]}")
                if len(raw) > MAX_DECODED_STREAM:
                    raise ValueError("Decoded stream exceeds the per-stream limit")
            self.decoded_total += len(raw)
            if self.decoded_total > MAX_DECODED_TOTAL:
                raise ParseLimit("Total decoded stream limit reached")
            self.decoded_cache[key] = raw
            return raw
        except (ValueError, zlib.error) as exc:
            self.limitations.append(f"Object {key[0]} {key[1]}: {exc}.")
            return None

    def parse_objects(self) -> None:
        parser = Syntax(self.data, self.limitations)
        position = 0
        while True:
            match = OBJECT.search(self.data, position)
            trailer = TRAILER.search(self.data, position)
            next_record = trailer if trailer and (not match or trailer.start() < match.start()) else match
            if not next_record:
                break
            line_start = max(position, self.data.rfind(b"\n", position, next_record.start()) + 1, self.data.rfind(b"\r", position, next_record.start()) + 1)
            if b"%" in self.data[line_start:next_record.start()]:
                newline = self.data.find(b"\n", next_record.end())
                carriage = self.data.find(b"\r", next_record.end())
                position = min(v for v in (newline, carriage, len(self.data)) if v >= 0)
                continue
            if next_record is trailer:
                if len(self.trailers) >= 100:
                    raise ParseLimit("Trailer count limit reached.")
                parser.pos = trailer.end()
                try:
                    value = parser.value()
                    if not isinstance(value, dict):
                        raise ValueError("Trailer is not a dictionary.")
                    self.trailers.append(value)
                except ParseLimit:
                    raise
                except ValueError as exc:
                    self.limitations.append(f"Trailer could not be parsed: {exc}")
                position = max(parser.pos, trailer.end())
                continue
            if len(self.records) >= MAX_OBJECTS:
                raise ParseLimit("Indirect object limit reached.")
            key = (int(match[1]), int(match[2]))
            parser.pos = match.end()
            try:
                value = parser.value()
                parser.skip()
                stream = None
                if self.data[parser.pos:parser.pos + 6] == b"stream":
                    if not isinstance(value, dict):
                        raise ValueError("Stream has no dictionary.")
                    start = parser.pos + 6
                    if self.data[start:start + 2] == b"\r\n":
                        start += 2
                    elif self.data[start:start + 1] in (b"\n", b"\r"):
                        start += 1
                    else:
                        raise ValueError("Invalid stream line ending.")
                    length = value.get("Length")
                    if type(length) is int and 0 <= length <= len(self.data) - start:
                        end = start + length
                        check = end
                        while check < len(self.data) and self.data[check] in SPACE:
                            check += 1
                        if self.data[check:check + 9] != b"endstream":
                            raise ValueError("Stream length does not match its terminator.")
                    else:
                        end = self.data.find(b"endstream", start)
                        check = end
                        if end < 0:
                            raise ValueError("Stream terminator missing.")
                        self.limitations.append(f"Object {key[0]} {key[1]}: stream boundary recovered without a direct validated length.")
                    stream = self.data[start:end]
                    parser.pos = check + 9
                    parser.skip()
                if self.data[parser.pos:parser.pos + 6] != b"endobj":
                    raise ValueError("Object terminator missing.")
                position = parser.pos + 6
                obj = {"key": key, "value": value, "stream": stream, "offset": match.start(), "compressed": False}
                if key in self.objects:
                    self.limitations.append("Repeated object identities found; all revisions are inspected, not only the reader's effective revision.")
                self.records.append(obj)
                self.objects[key] = obj
            except ParseLimit:
                raise
            except (ValueError, OverflowError) as exc:
                self.limitations.append(f"Object {key[0]} {key[1]} could not be parsed: {exc}")
                position = max(parser.pos, match.end())
        # Expand compressed object dictionaries, not image or page content streams.
        for obj in list(self.records):
            value = obj["value"]
            if not isinstance(value, dict) or _text(value.get("Type")) != "ObjStm":
                continue
            raw = self.decode(obj)
            count, first = value.get("N"), value.get("First")
            if raw is None:
                continue
            if type(count) is not int or type(first) is not int or not 0 <= count <= MAX_OBJECTS or not 0 <= first <= len(raw):
                self.limitations.append("Invalid compressed object-stream header.")
                continue
            try:
                header = raw[:first].split()
                if len(header) != count * 2:
                    raise ValueError("Object-stream index has an unexpected length")
                pairs = [(int(header[i]), int(header[i + 1])) for i in range(0, len(header), 2)]
                offsets = [offset for _, offset in pairs]
                if offsets != sorted(set(offsets)) or any(number < 0 or offset < 0 or first + offset >= len(raw) for number, offset in pairs):
                    raise ValueError("Invalid compressed object offsets")
                for index, (number, offset) in enumerate(pairs):
                    if len(self.records) >= MAX_OBJECTS:
                        raise ParseLimit("Expanded object limit reached.")
                    end = first + pairs[index + 1][1] if index + 1 < len(pairs) else len(raw)
                    inner = Syntax(raw[first + offset:end], self.limitations)
                    inner.tokens = parser.tokens
                    item = inner.value()
                    parser.tokens = inner.tokens
                    inner.skip()
                    if inner.pos != len(inner.data):
                        raise ValueError("Trailing bytes in compressed object")
                    key = (number, 0)
                    entry = {"key": key, "value": item, "stream": None, "offset": obj["offset"], "compressed": True}
                    if key in self.objects:
                        self.limitations.append("Compressed object identity conflicts with another revision.")
                    self.records.append(entry)
                    self.objects[key] = entry
            except (ValueError, OverflowError) as exc:
                self.limitations.append(f"Object stream could not be fully parsed: {exc}.")

    def add_destination(self, text: str, context: str, kind: str) -> None:
        if len(self.destinations) >= MAX_RECORDS:
            self.limitations.append("Destination evidence limit reached.")
            return
        self.destinations.append({"value": text[:2048], "context": context[:400], "kind": kind,
                                  "contacted": False, "note": "Recorded target only; no request was observed or made."})

    def script(self, value, context: str) -> None:
        raw = None
        if isinstance(value, Ref):
            obj = self.objects.get((value.number, value.generation))
            if obj and obj.get("stream") is not None:
                raw = self.decode(obj)
        if raw is None:
            resolved = self.resolve(value)
            if isinstance(resolved, bytes):
                raw = resolved
        if raw is None:
            self.limitations.append(f"JavaScript content could not be read at {context[:200]}.")
            return
        if len(self.scripts) >= MAX_RECORDS:
            self.limitations.append("JavaScript evidence limit reached.")
            return
        text = _text(raw)
        indicators = [label for pattern, label in (
            (r"\b(?:app\s*\.\s*launchURL|(?:this\s*\.\s*)?getURL|submitForm)\s*\(", "Possible URL opening or form submission"),
            (r"\b(?:exportDataObject|importDataObject|launchFile)\s*\(", "Possible file interaction"),
            (r"\b(?:eval|unescape|atob|fromCharCode)\s*\(", "Dynamic code or string decoding"),
        ) if re.search(pattern, text, re.I)]
        self.scripts.append({"context": context[:400], "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                             "preview": text[:2000], "preview_truncated": len(text) > 2000,
                             "indicators": indicators, "executed": False})
        for match in islice(URL.finditer(text), MAX_RECORDS):
            self.add_destination(match[0], context, "String in JavaScript; execution not established")

    def walk(self, value, context: str, depth: int = 0) -> None:
        self.walked += 1
        if depth > 40 or self.walked > MAX_TOKENS:
            raise ParseLimit("Evidence traversal limit reached.")
        if isinstance(value, Name):
            if value.value in self.name_counts:
                self.name_counts[value.value] += 1
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self.walk(item, f"{context}[{index}]"[:400], depth + 1)
        elif isinstance(value, dict):
            if "OpenAction" in value:
                self.actions.extend(self.action(value["OpenAction"], "Document open", context + " /OpenAction", set()))
            if "AA" in value:
                additional = self.resolve(value["AA"])
                if isinstance(additional, dict):
                    for event, action in additional.items():
                        trigger = f"Additional action /{event}" + (f" ({EVENT_LABELS[event]})" if event in EVENT_LABELS else "")
                        self.actions.extend(self.action(action, trigger, context + " /AA /" + event, set()))
                else:
                    self.limitations.append("Additional-action dictionary could not be resolved.")
            if "A" in value:
                self.actions.extend(self.action(value["A"], "Annotation or user interaction", context + " /A", set()))
            if _text(value.get("S")) in {"JavaScript", "Launch", "URI", "SubmitForm", "ImportData", "GoToR", "GoToE", "Rendition", "RichMediaExecute"}:
                self.actions.extend(self.action(value, "Trigger not established by this record", context, set()))
            if len(self.actions) > MAX_RECORDS:
                self.actions = self.actions[:MAX_RECORDS]
                self.limitations.append("Action evidence limit reached.")
            for key, item in value.items():
                if key in self.name_counts:
                    self.name_counts[key] += 1
                path = f"{context} /{key}"[:400]
                if key == "JS":
                    self.script(item, path)
                if key in {"URI", "F", "UF"}:
                    destination = self.resolve(item)
                    if isinstance(destination, bytes):
                        text = _text(destination)
                        self.add_destination(text, path, "PDF URI target" if key == "URI" else "File or form target; not necessarily a web request")
                if key in {"Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate"}:
                    item_text = self.resolve(item)
                    if isinstance(item_text, bytes):
                        self.metadata[key] = _text(item_text)[:500]
                self.walk(item, path, depth + 1)
            if _text(value.get("Type")) == "Filespec" or "EF" in value:
                if len(self.attachments) < MAX_RECORDS:
                    self.attachments.append({"context": context, "filename": _text(self.resolve(value.get("UF", value.get("F"))))[:500],
                                             "extracted": False, "note": "Attachment content was not extracted or executed."})

    def action(self, value, trigger: str, context: str, seen: set[tuple[int, int]], depth: int = 0) -> list[dict]:
        self.walked += 1
        if self.walked > MAX_TOKENS:
            raise ParseLimit("Action traversal limit reached.")
        if depth > 30:
            self.limitations.append("Action-chain depth limit reached.")
            return []
        if isinstance(value, Ref):
            key = (value.number, value.generation)
            if key in seen:
                self.limitations.append("Cyclic action chain encountered.")
                return []
            seen = seen | {key}
            context += f" -> {key[0]} {key[1]} R"
        value = self.resolve(value)
        if isinstance(value, list):
            # An OpenAction destination array is navigation, not executable code.
            if trigger == "Document open" and (not value or not isinstance(value[0], (dict, Ref))):
                return []
            return [record for item in value[:MAX_RECORDS] for record in self.action(item, trigger, context, seen, depth + 1)][:MAX_RECORDS]
        if not isinstance(value, dict):
            return []
        action_type = _text(self.resolve(value.get("S")))
        records = []
        if action_type:
            target = self.resolve(value.get("URI", value.get("F", value.get("Win"))))
            if isinstance(target, dict):
                target = self.resolve(target.get("UF", target.get("F")))
            records.append({"type": action_type[:100], "trigger": trigger, "context": context[:500],
                            "target": _text(target)[:1000] if isinstance(target, (bytes, Name)) else "Not recorded in this action",
                            "active_feature": action_type in {"JavaScript", "Launch", "SubmitForm", "ImportData", "GoToR", "GoToE", "URI", "Rendition", "RichMediaExecute"},
                            "note": "Behavior depends on the PDF reader, its settings, and user consent. This action was not executed."})
        if "Next" in value:
            records.extend(self.action(value["Next"], trigger, context + " /Next", seen, depth + 1))
        return records[:MAX_RECORDS]

    def script_tree(self, value, context: str, seen: set[tuple[int, int]], depth: int = 0) -> None:
        self.walked += 1
        if self.walked > MAX_TOKENS:
            raise ParseLimit("JavaScript name-tree traversal limit reached.")
        if depth > 30:
            self.limitations.append("JavaScript name-tree depth limit reached.")
            return
        if isinstance(value, Ref):
            key = (value.number, value.generation)
            if key in seen:
                self.limitations.append("Cyclic JavaScript name tree encountered.")
                return
            seen = seen | {key}
        value = self.resolve(value)
        if not isinstance(value, dict):
            self.limitations.append("JavaScript name tree could not be resolved.")
            return
        entries = self.resolve(value.get("Names", []))
        if not isinstance(entries, list) or len(entries) % 2:
            self.limitations.append("JavaScript name-tree entries are malformed.")
        else:
            if len(entries) > MAX_RECORDS * 2:
                self.limitations.append("JavaScript name-tree entry limit reached.")
            for index in range(1, min(len(entries), MAX_RECORDS * 2), 2):
                if len(self.actions) >= MAX_RECORDS:
                    self.limitations.append("Action evidence limit reached.")
                    break
                self.actions.extend(self.action(entries[index], "Document-level JavaScript registration (reader-dependent initialization)", context + " /Names", set()))
                self.actions = self.actions[:MAX_RECORDS]
        children = self.resolve(value.get("Kids", []))
        if isinstance(children, list):
            if len(children) > MAX_RECORDS:
                self.limitations.append("JavaScript name-tree child limit reached.")
            for child in children[:MAX_RECORDS]:
                self.script_tree(child, context + " /Kids", seen, depth + 1)
        else:
            self.limitations.append("JavaScript name-tree children are malformed.")

    def analyze(self, filename: str) -> dict:
        header = re.search(rb"%PDF-(\d\.\d)", self.data[:1024])
        if not header:
            raise ValueError("No PDF header was found within the first 1024 bytes.")
        if header.start() != 0:
            self.limitations.append("Bytes precede the PDF header; reader interpretation may differ.")
        eof = self.data.rstrip().endswith(b"%%EOF")
        if not eof:
            self.limitations.append("The final PDF EOF marker is missing or has trailing non-whitespace data.")
        if self.data.count(b"%%EOF") > 1:
            self.limitations.append("Multiple EOF markers: possible incremental revisions. Findings may include superseded objects.")
        if not re.search(rb"startxref\s+\d+\s+%%EOF", self.data):
            self.limitations.append("No conventional startxref/EOF pair was found.")
        try:
            self.parse_objects()
        except (ParseLimit, RecursionError, MemoryError) as exc:
            self.limitations.append(str(exc) or "Parsing resource limit reached.")
        if not self.records:
            self.limitations.append("No indirect objects could be inspected.")
        catalogs = 0
        try:
            for obj in self.records:
                context = f"Object {obj['key'][0]} {obj['key'][1]}" + (" (compressed)" if obj["compressed"] else "")
                self.walk(obj["value"], context)
                value = obj["value"]
                if not isinstance(value, dict):
                    continue
                if _text(value.get("Type")) == "Catalog":
                    catalogs += 1
                    names = self.resolve(value.get("Names"))
                    if isinstance(names, dict) and "JavaScript" in names:
                        self.script_tree(names["JavaScript"], context + " /Names /JavaScript", set())
        except (ParseLimit, RecursionError, MemoryError) as exc:
            self.limitations.append(str(exc) or "Evidence resource limit reached.")
        if catalogs != 1:
            self.limitations.append("A single unambiguous document catalog was not established.")
        encrypted = any(value.get("Encrypt") is not None for value in self.trailers)
        encrypted = encrypted or any(isinstance(obj["value"], dict) and _text(obj["value"].get("Type")) == "XRef" and obj["value"].get("Encrypt") is not None for obj in self.records)
        if encrypted:
            self.limitations.append("Encryption is present or indicated. Encrypted strings and streams were not decrypted; absence claims are unavailable.")
        unsupported = [name for name in ("XFA", "RichMedia") if self.name_counts[name]]
        if unsupported:
            self.limitations.append("Embedded XFA or rich-media behavior is not analyzed.")
        limits = list(dict.fromkeys(self.limitations))[:100]
        if len(self.actions) > MAX_RECORDS:
            self.actions = self.actions[:MAX_RECORDS]
            limits.append("Action evidence limit reached.")
        active = bool(self.scripts or any(a["active_feature"] for a in self.actions) or self.name_counts["JavaScript"] or self.name_counts["JS"] or self.name_counts["EmbeddedFile"] or self.attachments or unsupported)
        status = "Review features" if active else ("Analysis incomplete" if limits else "No supported active features found")
        js_indicated = bool(self.name_counts["JavaScript"] or self.name_counts["JS"] or self.scripts)
        opening = [row for row in self.actions if row["active_feature"] and (row["trigger"] == "Document open" or row["trigger"].startswith("Document-level JavaScript") or "(Page open)" in row["trigger"])]
        web_targets = sum(bool(re.match(r"^(?:https?|ftp)://", row["value"], re.I)) for row in self.destinations)
        answers = [
            {"question": "Does it contain JavaScript?", "answer": "JavaScript is present or indicated." if js_indicated else "No JavaScript observed in inspected objects.", "note": "Script presence is not proof of malware. Unreadable or obfuscated code may require separate analysis."},
            {"question": "Does anything run when it opens?", "answer": "Active document or page-open features are declared." if opening else "No supported active document-open action identified.", "note": "Reader execution was not tested. Page events can activate when pages display; interaction and initialization depend on the reader."},
            {"question": "Can it reach a website?", "answer": f"{web_targets} web target record(s) found." if web_targets else "No supported web target identified.", "note": "No request was made or observed. Scripts can construct destinations dynamically; hyperlinks can require a click."},
            {"question": "Does it contain attachments?", "answer": "Embedded-file references found." if self.attachments or self.name_counts["EmbeddedFile"] else "No embedded-file reference identified.", "note": "Attachment contents were not extracted or assessed."},
        ]
        if limits:
            for answer in answers:
                if answer["answer"].startswith("No "):
                    answer["answer"] = "Unable to establish from the limited analysis."
                answer["note"] += " Analysis is limited; missing evidence does not establish absence."
        return {
            "schema_version": 1, "tool_version": __version__, "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "file": {"name": Path(filename.replace("\\", "/")).name[:200], "bytes": len(self.data), "sha256": hashlib.sha256(self.data).hexdigest()},
            "structure": {"header": header[0].decode("ascii"), "header_offset": header.start(), "final_eof_marker": eof,
                          "object_count": len(self.records), "compressed_object_count": sum(obj["compressed"] for obj in self.records),
                          "catalog_count": catalogs, "encrypted_or_indicated": encrypted,
                          "xref_validation": "Not performed; object recovery is not full PDF conformance validation."},
            "assessment": {"label": status, "analysis_complete_within_supported_scope": not bool(limits), "malware_verdict": "Not determined",
                           "explanation": "Review the recorded actions and their triggers before opening this document." if active else "No supported active features were identified in the inspected objects. This does not establish that the document is safe.",
                           "next_step": "Keep the original closed. Validate its source and review the action evidence." if active or limits else "Verify the sender and purpose before opening. Static inspection cannot rule out reader exploits."},
            "name_counts": self.name_counts, "actions": self.actions, "javascript": self.scripts, "destinations": self.destinations,
            "answers": answers,
            "attachments": self.attachments, "metadata": self.metadata, "limitations": limits,
            "boundary": LIMITATION, "privacy": "Analysis stays on this computer. The original PDF is not retained by Inspector. Exported reports can contain filenames, document metadata, destinations, and bounded script excerpts.",
        }


def inspect_pdf(data: bytes, filename: str = "document.pdf") -> dict:
    """Pure analysis entry point for fixtures; production calls use a bounded worker."""
    if not data or len(data) > MAX_PDF_BYTES:
        raise ValueError("Select a nonempty PDF no larger than 25 MiB.")
    return Inspector(data).analyze(filename)


def inspect_pdf_isolated(data: bytes, filename: str = "document.pdf") -> dict:
    if not data or len(data) > MAX_PDF_BYTES:
        raise ValueError("Select a nonempty PDF no larger than 25 MiB.")
    try:
        result = subprocess.run([sys.executable, "-m", "macos_inspector.core.pdf_inspector"], input=data,
                                capture_output=True, timeout=WORKER_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("PDF analysis exceeded its 20-second limit. No complete result is available.") from exc
    if result.returncode != 0:
        raise ValueError("PDF analysis stopped because the file was invalid or a worker resource limit was reached. No complete result is available.")
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError("PDF result exceeded its output limit.")
    report = json.loads(result.stdout)
    if report["file"]["sha256"] != hashlib.sha256(data).hexdigest():
        raise ValueError("PDF worker identity check failed.")
    report["file"]["name"] = Path(filename.replace("\\", "/")).name[:200]
    return report


def _worker() -> int:
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        # Address-space limits work on Linux; macOS uses the timeout and decoded-byte bounds.
        if sys.platform != "darwin":
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        data = sys.stdin.buffer.read(MAX_PDF_BYTES + 1)
        print(json.dumps(inspect_pdf(data), ensure_ascii=True))
        return 0
    except (ValueError, MemoryError, RecursionError, OSError):
        return 1


if __name__ == "__main__":
    raise SystemExit(_worker())
