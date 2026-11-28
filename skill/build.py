"""Build the skill ZIP for marketplaces: copies docs/policy.md into the skill, then zips skill/mcp-guard/.
    python skill/build.py      ->  skill/mcp-guard-skill.zip
"""
import shutil
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def main():
    shutil.copyfile(ROOT / "docs" / "policy.md", HERE / "mcp-guard" / "reference" / "policy.md")
    out = HERE / "mcp-guard-skill.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted((HERE / "mcp-guard").rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(HERE).as_posix())
    print(out, [n for n in zipfile.ZipFile(out).namelist()])


if __name__ == "__main__":
    main()
