"""Trusted recipe registry (local design for a future community database).

A registry bundle is a folder:
    manifest.json   {"format": "legacyforge-registry/1", "name", "version", "created", "author",
                     "key_id", "recipes": [{"id", "file", "sha256", "recipe_version"}]}
    manifest.sig    base64 Ed25519 signature over the canonical manifest bytes
    recipes/*.yaml

Installation requires: a signature from a key in the local trust store, every
recipe file matching its listed SHA-256, no path escapes, and every recipe
passing strict schema validation. Popularity or download counts never count
as trust. Signing and verification need the optional `cryptography` package
(`pip install legacyforge[registry]`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import time
from pathlib import Path

from .fsutil import ensure_within, sha256_file
from .recipe import RecipeError, data_home, load_file, user_recipe_dir

FORMAT = "legacyforge-registry/1"


class RegistryError(Exception):
    pass


def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                                       Ed25519PublicKey)
        from cryptography.hazmat.primitives import serialization
    except ImportError as e:
        raise RegistryError("signing/verification needs the 'cryptography' package: "
                            "pip install legacyforge[registry]") from e
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def canonical(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def key_id(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()[:16]


def trust_dir() -> Path:
    return data_home() / "trusted_keys"


def generate_key(out_dir: Path) -> tuple[Path, str]:
    Priv, _, ser = _crypto()
    k = Priv.generate()
    raw_priv = k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    raw_pub = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    kid = key_id(raw_pub)
    priv = out_dir / f"{kid}.key"
    priv.write_text(base64.b64encode(raw_priv).decode())
    try:
        priv.chmod(0o600)
    except OSError:
        pass
    (out_dir / f"{kid}.pub").write_text(base64.b64encode(raw_pub).decode())
    return priv, kid


def trust_key(pub_file: Path) -> str:
    raw = base64.b64decode(Path(pub_file).read_text().strip(), validate=True)
    if len(raw) != 32:
        raise RegistryError("not an Ed25519 public key")
    kid = key_id(raw)
    trust_dir().mkdir(parents=True, exist_ok=True)
    (trust_dir() / f"{kid}.pub").write_text(base64.b64encode(raw).decode())
    return kid


def build_and_sign(bundle: Path, key_file: Path, *, name: str, version: str, author: str) -> dict:
    Priv, _, ser = _crypto()
    bundle = Path(bundle)
    raw = base64.b64decode(Path(key_file).read_text().strip())
    k = Priv.from_private_bytes(raw)
    pub = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    entries = []
    for p in sorted((bundle / "recipes").glob("*.y*ml")):
        r = load_file(p)  # never sign something that doesn't validate
        entries.append({"id": r.id, "file": f"recipes/{p.name}", "sha256": sha256_file(p),
                        "recipe_version": None})
    m = {"format": FORMAT, "name": name, "version": version, "author": author,
         "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "key_id": key_id(pub),
         "recipes": entries}
    (bundle / "manifest.json").write_text(json.dumps(m, indent=2))
    (bundle / "manifest.sig").write_text(base64.b64encode(k.sign(canonical(m))).decode())
    return m


def verify(bundle: Path) -> dict:
    _, Pub, _ = _crypto()
    bundle = Path(bundle)
    try:
        m = json.loads((bundle / "manifest.json").read_text())
        sig = base64.b64decode((bundle / "manifest.sig").read_text().strip(), validate=True)
    except (OSError, ValueError) as e:
        raise RegistryError(f"unreadable bundle: {e}") from e
    if m.get("format") != FORMAT:
        raise RegistryError(f"unsupported registry format {m.get('format')!r}")
    kid = m.get("key_id", "")
    pub_file = trust_dir() / f"{kid}.pub"
    if not kid.isalnum() or not pub_file.exists():
        raise RegistryError(f"signing key {kid!r} is not in your trust store "
                            f"(legacyforge registry trust <key.pub>)")
    pub = Pub.from_public_bytes(base64.b64decode(pub_file.read_text().strip()))
    try:
        pub.verify(sig, canonical(m))
    except Exception as e:
        raise RegistryError("signature does not verify: the bundle was modified or signed by "
                            "a different key") from e
    for entry in m.get("recipes", []):
        path = ensure_within(bundle, Path(entry["file"]))
        if sha256_file(path) != entry["sha256"]:
            raise RegistryError(f"{entry['file']}: hash does not match the signed manifest")
        try:
            r = load_file(path)
        except RecipeError as e:
            raise RegistryError(f"{entry['file']}: {e}") from e
        if r.id != entry["id"]:
            raise RegistryError(f"{entry['file']}: recipe id {r.id!r} != manifest id {entry['id']!r}")
    return m


def install(bundle: Path) -> list[str]:
    m = verify(bundle)
    dest = user_recipe_dir()
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for entry in m["recipes"]:
        src = ensure_within(Path(bundle), Path(entry["file"]))
        shutil.copy2(src, dest / f"{entry['id']}.yaml")
        out.append(entry["id"])
    return out
