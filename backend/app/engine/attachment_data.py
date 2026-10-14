"""File-type reference data for attachment metadata analysis (names and MIME types only)."""

# Run code when opened: programs, scripts, installers, shortcuts, control-panel items.
EXECUTABLE_EXTENSIONS = frozenset(
    {
        "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "msix", "appx", "js", "jse",
        "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "jar", "lnk", "cpl", "reg", "msc",
        "dll", "application", "gadget", "inf", "scf", "url", "iqy", "sct", "chm", "xll",
    }
)
# Office formats that can carry macros by design.
MACRO_EXTENSIONS = frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"})
# Rendered locally in a browser: common carriers of fake login pages.
HTML_EXTENSIONS = frozenset({"html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg"})
# Disk images: used to deliver executables past "downloaded from the internet" protections.
DISK_IMAGE_EXTENSIONS = frozenset({"iso", "img", "vhd", "vhdx"})
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj", "lzh", "bz2", "xz"})
# Extensions people expect to be harmless documents or media - the bait in double extensions.
DOCUMENT_LIKE_EXTENSIONS = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "mp3", "mp4"}
)

# Declared MIME type -> broad family, for extension/type consistency. Generic types such as
# application/octet-stream say nothing and are ignored.
MIME_FAMILIES = {
    "application/pdf": "document",
    "application/msword": "document",
    "application/vnd.ms-excel": "document",
    "application/vnd.ms-powerpoint": "document",
    "application/rtf": "document",
    "text/plain": "text",
    "text/csv": "text",
    "text/html": "html",
    "application/xhtml+xml": "html",
    "image/svg+xml": "html",
    "application/zip": "archive",
    "application/x-zip-compressed": "archive",
    "application/x-rar-compressed": "archive",
    "application/vnd.rar": "archive",
    "application/x-7z-compressed": "archive",
    "application/gzip": "archive",
    "application/x-msdownload": "executable",
    "application/x-msdos-program": "executable",
    "application/x-dosexec": "executable",
    "application/vnd.microsoft.portable-executable": "executable",
    "application/x-ms-shortcut": "executable",
    "application/hta": "executable",
    "application/javascript": "executable",
    "text/javascript": "executable",
}
MIME_PREFIX_FAMILIES = {
    "image/": "image",
    "audio/": "media",
    "video/": "media",
    "application/vnd.openxmlformats-officedocument.": "document",
}

EXTENSION_FAMILIES = {
    **{e: "document" for e in ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf")},
    **{e: "text" for e in ("txt", "csv")},
    **{e: "image" for e in ("jpg", "jpeg", "png", "gif", "bmp", "webp")},
    **{e: "media" for e in ("mp3", "mp4", "wav", "mov")},
    **{e: "html" for e in HTML_EXTENSIONS},
    **{e: "archive" for e in ("zip", "rar", "7z", "gz", "tgz")},
    **{e: "executable" for e in EXECUTABLE_EXTENSIONS},
}


def mime_family(content_type: str | None) -> str | None:
    if not content_type:
        return None
    mime = content_type.split(";")[0].strip().lower()
    if mime in MIME_FAMILIES:
        return MIME_FAMILIES[mime]
    return next((family for prefix, family in MIME_PREFIX_FAMILIES.items() if mime.startswith(prefix)), None)
