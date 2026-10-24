"""Normalise document metadata to the student's name.

The python-pptx default template carries 'Steve Canny' as lastModifiedBy and a
'generated using python-pptx' comment, both visible in PowerPoint's File > Info.
Pandoc-produced documents likewise leave author fields empty. This rewrites those
fields for every deliverable in docs/.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import zipfile

from pptx import Presentation

AUTHOR = "Rudra Pratap"
DOCS = pathlib.Path("docs")

PPTX_TITLE = "Aegis-SOC — Cloud-native AI security operations"
PPTX_SUBJECT = "Advanced Cloud Computing — M.Tech Semester 3"


def fix_pptx(path: pathlib.Path) -> None:
    prs = Presentation(str(path))
    cp = prs.core_properties
    cp.author = AUTHOR
    cp.last_modified_by = AUTHOR
    cp.title = PPTX_TITLE
    cp.subject = PPTX_SUBJECT
    cp.keywords = "SOC, MITRE ATT&CK, LLM triage, prompt injection, cloud"
    cp.comments = ""
    cp.category = "Project presentation"
    prs.save(str(path))
    print(f"pptx metadata set: {path.name}")


CORE_PATCHES = (
    (r"<dc:creator>.*?</dc:creator>", f"<dc:creator>{AUTHOR}</dc:creator>"),
    (r"<cp:lastModifiedBy>.*?</cp:lastModifiedBy>", f"<cp:lastModifiedBy>{AUTHOR}</cp:lastModifiedBy>"),
)


def fix_ooxml(path: pathlib.Path) -> None:
    """Rewrite docProps/core.xml inside a .docx (or any OOXML zip)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with zipfile.ZipFile(path) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "docProps/core.xml":
                txt = data.decode("utf-8")
                for pattern, repl in CORE_PATCHES:
                    txt = re.sub(pattern, repl, txt)
                data = txt.encode("utf-8")
            zout.writestr(item, data)
    shutil.move(str(tmp), str(path))
    print(f"core.xml rewritten: {path.name}")


def main() -> None:
    for pptx in DOCS.glob("*.pptx"):
        fix_pptx(pptx)
    for docx in DOCS.glob("*.docx"):
        fix_ooxml(docx)


if __name__ == "__main__":
    main()
