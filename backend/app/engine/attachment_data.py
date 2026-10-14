"""File-type reference data for attachment metadata analysis (names and declared types only)."""

# Run code when opened: programs, scripts, installers, shortcuts, control-panel items.
EXECUTABLE_EXTENSIONS = frozenset(
    {
        "exe", "scr", "com", "pif", "bat", "cmd", "msi", "js", "jse", "vbs", "vbe", "wsf",
        "hta", "ps1", "jar", "lnk", "cpl", "reg", "dll", "chm",
    }
)
# Office formats that can carry macros by design.
MACRO_EXTENSIONS = frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam"})
# Web pages (fake login forms) and disk images (used to smuggle programs past warnings).
RISKY_FORMAT_EXTENSIONS = frozenset({"html", "htm", "shtml", "svg", "mht", "iso", "img", "vhd", "vhdx"})
# What people expect to be harmless - the bait in a double extension like invoice.pdf.exe.
DOCUMENT_LIKE_EXTENSIONS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png"})

# Broad file families, to compare a file's extension with the MIME type the email declares.
# Generic declared types (application/octet-stream) say nothing and are ignored.
EXTENSION_FAMILIES = {
    **{e: "document" for e in ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx")},
    **{e: "image" for e in ("jpg", "jpeg", "png", "gif")},
    **{e: "html" for e in ("html", "htm", "svg")},
    **{e: "executable" for e in EXECUTABLE_EXTENSIONS},
}
_MIME_FAMILIES = {
    "application/pdf": "document",
    "application/msword": "document",
    "application/vnd.ms-excel": "document",
    "application/vnd.ms-powerpoint": "document",
    "text/html": "html",
    "image/svg+xml": "html",
    "application/x-msdownload": "executable",
    "application/x-msdos-program": "executable",
    "application/x-dosexec": "executable",
    "application/javascript": "executable",
}
_MIME_PREFIXES = {"image/": "image", "application/vnd.openxmlformats-officedocument.": "document"}


def mime_family(content_type: str | None) -> str | None:
    if not content_type:
        return None
    mime = content_type.split(";")[0].strip().lower()
    if mime in _MIME_FAMILIES:
        return _MIME_FAMILIES[mime]
    return next((family for prefix, family in _MIME_PREFIXES.items() if mime.startswith(prefix)), None)
