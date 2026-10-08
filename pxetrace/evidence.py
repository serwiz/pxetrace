"""Extract attributable plaintext credentials, never binary string guesses."""
from __future__ import annotations

import configparser
import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath


def local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def text_content(data: bytes) -> str | None:
    encodings: tuple[str, ...]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings = ("utf-16",)
    elif b"\x00" in data[:128]:
        encodings = ("utf-16le", "utf-16be")
    else:
        encodings = ("utf-8-sig",)
    for encoding in encodings:
        try:
            text = data.decode(encoding).rstrip("\x00")
        except UnicodeError:
            continue
        if all(char.isprintable() or char in "\r\n\t" for char in text):
            return text
    return None


def _normal(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _plain(value: str) -> bool:
    # References and ciphertext are not evidence of a recovered password.
    if not value or value.casefold() in {"none", "null", "redacted", "[vide]"}:
        return False
    if value.casefold().startswith(("[masqué", "[redacted")):
        return False
    if re.fullmatch(r"\*+|[xX]+|\$[\w:]+|<.*>", value):
        return False
    if re.search(r"%[A-Za-z_][\w]*%|\$\{[^}]+\}|\{\{.*?\}\}", value):
        return False
    return not (len(value) >= 64 and re.fullmatch(r"[0-9a-fA-F]+", value))


@dataclass(frozen=True)
class CredentialEvidence:
    account: str
    secret: str
    field: str
    source: str
    context: str
    sha256: str
    kind: str = "mot de passe"
    validation: str = "valeur extraite; connexion non testée"

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class CredentialScan:
    credentials: list[CredentialEvidence]
    limitation: str | None = None


def _from_fields(fields: dict[str, tuple[str, str]], source: str, context: str, digest: str) -> list[CredentialEvidence]:
    result = []
    for normal, (key, value) in fields.items():
        # Settings and descriptions mentioning passwords are not credentials.
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", key):
            continue
        if re.fullmatch(r"(?:require|requires|use|enable|enabled|disable|disabled|skip|promptfor|save|store|remember|allow|has|is|can|mask|protect)(?:pxe|boot|strong|complex|networkaccess|domainadmin|admin|user)?(?:password|passwd|passphrase|pwd|token|secret)", normal):
            continue
        if not _plain(value):
            continue
        password = any(normal.endswith(suffix) for suffix in ("password", "passwd", "passphrase", "pwd"))
        token = normal.endswith(("apitoken", "apikey", "secret", "token"))
        if not password and not token:
            continue
        account_candidates: list[str] = []
        domain_candidates: list[str] = []
        for suffix in ("password", "passwd", "passphrase", "pwd"):
            if normal.endswith(suffix):
                prefix = normal[:-len(suffix)]
                if prefix:
                    account_candidates.extend(prefix + ending for ending in ("username", "user", "userid", "account", "name", ""))
                    domain_candidates.extend([prefix + "domain", prefix + "domainname"])
        # Common Windows deployment pairs with different field prefixes.
        account_candidates.extend({
            "osdjoinpassword": ["osdjoinaccount"],
            "domainadminpassword": ["domainadmin"],
            "userpassword": ["userid", "username"],
        }.get(normal, []))
        # Never use a policy/collection variable's Name as an account. A
        # prefixed password must not inherit an unrelated generic Username.
        if normal in {"password", "passwd", "passphrase", "pwd", "userpassword", "secret", "apikey", "apitoken", "token"}:
            account_candidates.extend(["username", "userid", "account", "user"])
            domain_candidates.extend(["userdomain", "domain"])
        accounts = [fields[name][1] for name in account_candidates if name in fields and _plain(fields[name][1]) and name != normal]
        account = accounts[0] if accounts else "non précisé"
        domain = next((fields[name][1] for name in domain_candidates if name in fields and _plain(fields[name][1])), "")
        if domain and account != "non précisé" and "\\" not in account and "@" not in account:
            account = domain + "\\" + account
        result.append(CredentialEvidence(account, value, key, source, context, digest,
                                         "mot de passe" if password else "jeton / clé API"))
    return result


def inspect_credentials(data: bytes, *, source: str) -> CredentialScan:
    # Scripts need a language-aware reader. Do not feed commands or expressions
    # into an INI parser and mislabel them as literal passwords.
    if PurePosixPath(source.replace("\\", "/")).suffix.lower() in {".ps1", ".cmd", ".bat", ".ipxe"}:
        return CredentialScan([], "script non interprété")
    text = text_content(data)
    if text is None:
        return CredentialScan([], "contenu binaire ou encodage non pris en charge")
    digest = hashlib.sha256(data).hexdigest()
    result: list[CredentialEvidence] = []
    undecoded = False
    if text.lstrip().startswith("<"):
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return CredentialScan([], "XML invalide")

        def visit(node: ET.Element, context: str) -> None:
            nonlocal undecoded
            if node.get("secret") == "1":
                undecoded = True
                return
            if any(local_name(child.tag).casefold() == "plaintext" and (child.text or "").strip().casefold() == "false" for child in node):
                undecoded = True
                return
            tag = local_name(node.tag)
            context = context + "/" + tag + ("[" + node.get("name", node.get("class", "")) + "]" if node.get("name") or node.get("class") else "")
            fields: dict[str, tuple[str, str]] = {}
            for child in node:
                if child.get("secret") == "1":
                    undecoded = True
                    continue
                if child.get("type", "").casefold() in {"11", "boolean", "bool"}:
                    continue
                key = child.get("name") or child.get("property") or local_name(child.tag)
                value_node = next((item for item in child if local_name(item.tag).lower() == "value"), None)
                value = value_node.text if value_node is not None else child.text
                # Unattend PlainText=false requires another decoding step.
                if any(local_name(item.tag).lower() == "plaintext" and (item.text or "").lower() == "false" for item in child):
                    undecoded = True
                    continue
                if (value and not list(child)) or value_node is not None:
                    fields[_normal(key)] = (key, value or "")
            # Collection variables store their key and value as properties.
            if "name" in fields and "value" in fields:
                key, value = fields["name"][1], fields["value"][1]
                fields[_normal(key)] = (key, value)
            if tag.casefold() == "localaccount" and "name" in fields:
                fields["username"] = ("Username", fields["name"][1])
            for key, value in node.attrib.items():
                if _normal(key) != "secret" or value not in {"0", "1", "true", "false"}:
                    fields[_normal(key)] = (key, value)
            result.extend(_from_fields(fields, source, context, digest))
            for child in node:
                if child.get("secret") != "1":
                    visit(child, context)

        visit(root, "")
    else:
        # Deployment INI files: do not associate a user in another section.
        parser = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
        parser.optionxform = str  # type: ignore[assignment]
        try:
            parser.read_string(text if re.search(r"(?m)^\s*\[", text) else "[configuration]\n" + text)
        except configparser.Error:
            return CredentialScan([], "configuration non interprétée")
        for section in parser.sections():
            fields = {_normal(key): (key, value) for key, value in parser.items(section)}
            result.extend(_from_fields(fields, source, section, digest))
    return CredentialScan(list(dict.fromkeys(result)), "valeurs protégées non décodées" if undecoded else None)


def extract_credentials(data: bytes, *, source: str) -> list[CredentialEvidence]:
    return inspect_credentials(data, source=source).credentials
