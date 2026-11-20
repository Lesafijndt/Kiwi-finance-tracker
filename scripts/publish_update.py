"""Verify signed Kiwi APKs, stage releases, and submit them to the OTA workflow."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO = "Lesafijndt/Kiwi-finance-tracker"
PACKAGE = "com.pulse.wallet"
CERT = "7310d761ef7f21deaa0b0f0a7c752603d4f2f0558910f69ba4e111b40266654c"
WORKFLOW = "publish-ota.yml"
MAX_APK = 200 * 1024 * 1024
MAX_MANIFEST = 256 * 1024
ASSET_NAMES = {"Kiwi-Finance.apk", "kiwi-update.json"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(args, env=None):
    process = subprocess.run([str(value) for value in args], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", env=env)
    if process.returncode:
        raise RuntimeError("Command failed: " + str(args[0]) + "\n" + process.stderr[:1200])
    return process.stdout


def github_environment():
    env = dict(os.environ)
    env.pop("GH_DEBUG", None)
    if env.get("GH_TOKEN") or env.get("GITHUB_TOKEN"):
        return env
    query = "protocol=https\nhost=github.com\nusername=Lesafijndt\n\n"
    env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never")
    process = subprocess.run(["git", "-c", "credential.interactive=false", "credential", "fill"],
                             input=query, capture_output=True, text=True, env=env)
    values = dict(line.split("=", 1) for line in process.stdout.splitlines() if "=" in line) if process.returncode == 0 else {}
    if values.get("password"):
        env["GH_TOKEN"] = values["password"]
    return env


class GitHub:
    def __init__(self, executable="gh"):
        self.executable = executable
        self.env = github_environment()

    def __call__(self, *args):
        return run([self.executable, *args], self.env)

    def api(self, path, optional=False):
        process = subprocess.run([self.executable, "api", f"repos/{REPO}/{path}"],
                                 capture_output=True, text=True, encoding="utf-8", env=self.env)
        if optional and process.returncode and "(HTTP 404)" in process.stderr:
            return None
        require(process.returncode == 0, "GitHub API failed: " + process.stderr[:1200])
        return json.loads(process.stdout)

    def release(self, tag):
        stable_tag(tag)
        release = self.api(f"releases/tags/{tag}", optional=True)
        if release is not None:
            return release
        # The tag endpoint can omit drafts. Authenticated listing includes them.
        pages = json.loads(self("api", f"repos/{REPO}/releases?per_page=100", "--paginate", "--slurp"))
        matches = [item for page in pages for item in page if item["tag_name"] == tag]
        require(len(matches) <= 1, "Multiple releases use this tag")
        return matches[0] if matches else None


def stable_tag(tag):
    require(isinstance(tag, str) and re.fullmatch(r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", tag),
            "OTA releases require a stable vMAJOR.MINOR.PATCH tag")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def verify_apk(apk, sdk, java):
    require(apk.is_file() and 0 < apk.stat().st_size <= MAX_APK, "APK size outside update limit")
    builds = [folder for folder in (sdk / "build-tools").iterdir() if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", folder.name)]
    require(builds, "Android build tools are required")
    tools = max(builds, key=lambda folder: tuple(map(int, folder.name.split("."))))
    badging = run([tools / ("aapt2.exe" if os.name == "nt" else "aapt2"), "dump", "badging", apk])
    line = next(line for line in badging.splitlines() if line.startswith("package:"))
    package = re.search(r"name='([^']+)'", line)[1]
    code = int(re.search(r"versionCode='([0-9]+)'", line)[1])
    version = re.search(r"versionName='([^']+)'", line)[1]
    require(package == PACKAGE and 0 < code <= 2147483647, "Wrong APK package or version code")
    stable_tag("v" + version)
    signature = run([java, "-jar", tools / "lib/apksigner.jar", "verify", "--print-certs", apk])
    signers = re.findall(r"certificate SHA-256 digest: ([a-fA-F0-9]{64})", signature)
    require(len(signers) == 1 and signers[0].lower() == CERT, "APK signing identity changed")
    return dict(packageName=package, versionCode=code, versionName=version,
                sha256=digest(apk), sizeBytes=apk.stat().st_size)


def validate_manifest(manifest, tag, apk_info=None):
    stable_tag(tag)
    require(manifest.get("schemaVersion") == 1 and type(manifest.get("schemaVersion")) is int, "Invalid manifest schema")
    require(manifest.get("packageName") == PACKAGE, "Invalid manifest package")
    require(type(manifest.get("versionCode")) is int and 0 < manifest["versionCode"] <= 2147483647, "Invalid version code")
    require(manifest.get("versionName") == tag[1:], "Tag and version differ")
    require(manifest.get("apkUrl") == f"https://github.com/{REPO}/releases/download/{tag}/Kiwi-Finance.apk", "Unexpected APK URL")
    require(isinstance(manifest.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"]), "Invalid APK checksum")
    require(type(manifest.get("sizeBytes")) is int and 0 < manifest["sizeBytes"] <= MAX_APK, "Invalid APK size")
    notes = manifest.get("notes", "")
    require(isinstance(notes, str) and len(notes) <= 4000 and all((ord(char) >= 32 or char in "\n\t") and ord(char) != 127 for char in notes), "Invalid release notes")
    if apk_info is not None:
        require(all(manifest.get(key) == value for key, value in apk_info.items()), "Manifest does not describe the signed APK")


def read_manifest(path):
    require(path.is_file() and 0 < path.stat().st_size <= MAX_MANIFEST, "Manifest size outside update limit")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_assets(release, tag, expected=None):
    require(release["tag_name"] == tag and not release["prerelease"], "Wrong release or prerelease")
    assets = release["assets"]
    require(len(assets) == 2 and {asset["name"] for asset in assets} == ASSET_NAMES, "Release must contain exactly the APK and OTA manifest")
    for asset in assets:
        limit = MAX_APK if asset["name"] == "Kiwi-Finance.apk" else MAX_MANIFEST
        require(asset["state"] == "uploaded" and 0 < asset["size"] <= limit, "Incomplete or oversized release asset")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest") or ""), "GitHub asset checksum missing")
        if expected is not None:
            require(asset["digest"] == "sha256:" + expected[asset["name"]], "GitHub asset checksum differs")


def asset_snapshot(release):
    return (release["id"], release["tag_name"], release["draft"], release["prerelease"],
            sorted((asset["id"], asset["name"], asset["size"], asset["digest"]) for asset in release["assets"]))


def verify_public_version(gh, code, same_tag=None):
    latest = gh.api("releases/latest", optional=True)
    if latest is None:
        return
    tag = latest["tag_name"]
    stable_tag(tag)
    validate_assets(latest, tag)
    with tempfile.TemporaryDirectory(prefix="kiwi-current-") as folder:
        gh("release", "download", tag, "--repo", REPO, "--pattern", "kiwi-update.json", "--dir", folder)
        path = Path(folder) / "kiwi-update.json"
        metadata = next(asset for asset in latest["assets"] if asset["name"] == path.name)
        require(metadata["digest"] == "sha256:" + digest(path), "Public manifest checksum differs")
        manifest = read_manifest(path)
        validate_manifest(manifest, tag)
    require(code > manifest["versionCode"] or (tag == same_tag and code == manifest["versionCode"]),
            "Release is not newer than the public OTA channel")


def finalize(gh, tag, sdk, java):
    stable_tag(tag)
    release = gh.release(tag)
    require(release is not None, "Release draft does not exist")
    validate_assets(release, tag)
    with tempfile.TemporaryDirectory(prefix="kiwi-verify-") as folder:
        for name in sorted(ASSET_NAMES):
            gh("release", "download", tag, "--repo", REPO, "--pattern", name, "--dir", folder)
        directory = Path(folder)
        expected = {name: digest(directory / name) for name in ASSET_NAMES}
        validate_assets(release, tag, expected)
        info = verify_apk(directory / "Kiwi-Finance.apk", sdk, java)
        manifest = read_manifest(directory / "kiwi-update.json")
        validate_manifest(manifest, tag, info)
    if not release["draft"]:
        print("Verified already-published release " + tag)
        return
    verify_public_version(gh, info["versionCode"])
    current = gh.release(tag)
    require(current is not None and asset_snapshot(current) == asset_snapshot(release), "Release changed during verification; retry")
    gh("release", "edit", tag, "--repo", REPO, "--draft=false", "--latest")
    published = gh.release(tag)
    require(published is not None and not published["draft"], "Publication was not confirmed")
    print(f"Published https://github.com/{REPO}/releases/tag/{tag}")


def stage_release(args):
    apk = args.apk.resolve(strict=True)
    info = verify_apk(apk, args.sdk, args.java)
    tag = "v" + info["versionName"]
    stage = args.out.resolve() / tag
    stage.mkdir(parents=True, exist_ok=True)
    binary = stage / "Kiwi-Finance.apk"
    if binary.resolve() != apk:
        shutil.copy2(apk, binary)
    notes = args.notes.read_text(encoding="utf-8") if args.notes else "Kiwi improvements and fixes. Install over the existing app to preserve your data."
    manifest = dict(schemaVersion=1, **info,
                    apkUrl=f"https://github.com/{REPO}/releases/download/{tag}/Kiwi-Finance.apk", notes=notes)
    validate_manifest(manifest, tag, info)
    manifest_path = stage / "kiwi-update.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    note_path = stage / "release-notes.md"
    note_path.write_text(notes + "\n", encoding="utf-8")
    print(json.dumps({"stage": str(stage), **info}, ensure_ascii=False), flush=True)
    return tag, stage, manifest


def submit_release(args, tag, stage, manifest):
    gh = GitHub(args.gh)
    require(json.loads(gh("api", "user"))["login"].lower() == "lesafijndt", "Wrong publishing account")
    existing = gh.release(tag)
    expected = {name: digest(stage / name) for name in ASSET_NAMES}
    if existing is not None and not existing["draft"]:
        validate_assets(existing, tag, expected)
        print("Identical release is already published " + tag)
        return
    verify_public_version(gh, manifest["versionCode"])
    if existing is not None:
        require(not existing["prerelease"], "OTA draft must be stable")
        if args.replace_draft:
            gh("release", "upload", tag, stage / "Kiwi-Finance.apk", stage / "kiwi-update.json", "--repo", REPO, "--clobber")
    else:
        gh("release", "create", tag, stage / "Kiwi-Finance.apk", stage / "kiwi-update.json", "--repo", REPO,
           "--draft", "--target", "main", "--title", "Kiwi Finance " + manifest["versionName"],
           "--notes-file", stage / "release-notes.md")
    release = gh.release(tag)
    require(release is not None and release["draft"], "Draft state changed; retry")
    validate_assets(release, tag, expected)
    if args.submit:
        gh("workflow", "run", WORKFLOW, "--repo", REPO, "--ref", "main", "-f", "tag=" + tag)
        print(f"Submitted {tag}. Follow https://github.com/{REPO}/actions/workflows/{WORKFLOW}")
    elif args.publish:
        finalize(gh, tag, args.sdk, args.java)
    else:
        print("Draft uploaded and server checksums verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--java", default="java")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--notes", type=Path)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--draft-only", action="store_true")
    actions.add_argument("--publish", action="store_true")
    actions.add_argument("--submit", action="store_true", help="Upload a verified draft and start automatic OTA publication")
    actions.add_argument("--finalize", metavar="TAG", help="Verify a submitted release and publish it, used by the workflow")
    parser.add_argument("--replace-draft", action="store_true")
    args = parser.parse_args()
    if args.finalize:
        require(not args.apk and not args.out and not args.notes and not args.replace_draft, "Finalize accepts only a release tag and verification tools")
        finalize(GitHub(args.gh), args.finalize, args.sdk, args.java)
        return
    require(args.apk is not None and args.out is not None, "Specify --apk and --out")
    tag, stage, manifest = stage_release(args)
    if args.draft_only or args.publish or args.submit:
        submit_release(args, tag, stage, manifest)


if __name__ == "__main__":
    main()
