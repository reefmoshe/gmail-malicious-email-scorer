import pytest

from helpers import check_status, counted, finding, gmail_auth, run


def A(name, content_type=None, size=1000):
    return {"filename": name, "content_type": content_type, "size": size}


def attachments_only(*files):
    return run(sender="A <a@acme.com>", auth_results=gmail_auth("acme.com"), attachments=list(files))


def test_no_attachments_is_not_applicable_and_missing_data_not_available():
    assert check_status(attachments_only(), "attachments") == "not_applicable"
    assert check_status(run(sender="A <a@acme.com>"), "attachments") == "not_available"


@pytest.mark.parametrize(
    "files",
    [
        [A("report.pdf", "application/pdf")],
        [A("notes.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")],
        [A("photo.JPG", "image/jpeg"), A("budget.xlsx", "application/octet-stream")],
        [A("archive.tar.gz", "application/gzip")],  # .tar is not a document bait: no double extension
        [A("Q3 report.final.pdf", "application/pdf")],
    ],
)
def test_ordinary_business_attachments_are_clean_or_minor(files):
    result = attachments_only(*files)
    assert all(points <= 8 for points in counted(result).values())
    assert result.verdict == "LOW_RISK"


@pytest.mark.parametrize(
    "name, signal, points",
    [
        ("setup.exe", "ATT_EXECUTABLE", 30),
        ("run.JS", "ATT_EXECUTABLE", 30),
        ("shortcut.lnk", "ATT_EXECUTABLE", 30),
        ("invoice.xlsm", "ATT_MACRO_DOC", 20),
        ("files.iso", "ATT_DISK_IMAGE", 15),
        ("receipt.html", "ATT_HTML", 15),
        ("logo.svg", "ATT_HTML", 15),
        ("docs.zip", "ATT_ARCHIVE", 8),
    ],
)
def test_risky_file_types(name, signal, points):
    assert counted(attachments_only(A(name))) == {signal: points}


def test_trailing_dots_and_spaces_do_not_hide_the_real_extension():
    assert "ATT_EXECUTABLE" in counted(attachments_only(A("invoice.exe. ")))


def test_double_extension_reinforces_the_executable_finding():
    result = attachments_only(A("invoice.pdf.exe", "application/x-msdownload"))
    assert counted(result) == {"ATT_EXECUTABLE": 30, "ATT_DOUBLE_EXTENSION": 5}
    assert finding(result, "ATT_DOUBLE_EXTENSION").score_status == "reinforcing"


def test_executable_alone_is_suspicious_not_malicious():
    result = attachments_only(A("invoice.pdf.exe"))
    assert result.verdict == "SUSPICIOUS"


def test_right_to_left_override_is_detected_and_made_visible():
    result = attachments_only(A("invoice‮fdp.exe"))
    deceptive = finding(result, "ATT_DECEPTIVE_NAME")
    assert "[U+202E]" in deceptive.evidence[0]
    assert deceptive.score_status == "reinforcing"


def test_whitespace_padding_before_extension():
    assert "ATT_DECEPTIVE_NAME" in counted(attachments_only(A("statement.pdf              .zip")))


def test_declared_type_contradicting_the_name():
    result = attachments_only(A("invoice.pdf", "text/html"))
    assert counted(result) == {"ATT_TYPE_MISMATCH": 5}


def test_generic_declared_type_is_not_a_mismatch():
    assert counted(attachments_only(A("invoice.pdf", "application/octet-stream"))) == {}


def test_several_files_count_each_signal_once_and_respect_the_cap():
    result = attachments_only(A("a.exe"), A("b.scr"), A("c.docm"), A("d.iso"), A("e.html"))
    assert len(finding(result, "ATT_EXECUTABLE").evidence) == 2
    category = next(c for c in result.categories if c.id == "attachments")
    assert (category.score, category.cap) == (35, 35)


def test_files_without_extension_or_with_odd_names_do_not_crash():
    result = attachments_only(A("README"), A("."), A("...."), A("‮"), A("a" * 255))
    assert check_status(result, "attachments") == "completed"


def test_attachment_payload_limits():
    from pydantic import ValidationError

    from app.schemas import EmailMessage

    for bad in ([A("x" * 256)], [A("a.pdf", size=-1)], [A("a.pdf")] * 31, [{"filename": "a", "extra": 1}]):
        with pytest.raises(ValidationError):
            EmailMessage(sender="a@b.com", attachments=bad)
