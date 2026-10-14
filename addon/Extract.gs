/**
 * Reads ONLY the currently opened message, using the short-lived access token
 * Gmail passes in the event object (scope: gmail.addons.current.message.readonly).
 *
 * Data minimization: selected headers, a minimized form of each link, attachment metadata
 * (name, type, size - never contents), and at most 8,000 characters of plain text with every
 * web address removed. The backend analyzes the text in memory and never logs or stores it.
 */

// Must match the max_length limits in backend/app/schemas.py.
var FIELD_LIMITS = {
  subject: 1000,
  sender: 500,
  reply_to: 500,
  return_path: 500,
  date: 100,
  auth_results: 5000,
  link_url: 600,
  link_text: 200,
  attachment_name: 255,
  attachment_type: 200,
  body_text: 8000
};
var MAX_LINKS = 50;
var MAX_ATTACHMENTS = 30;
var MAX_BODY_CHARS = 300000;  // bounds the work done on very large messages

function extractMessageMetadata(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);
  var date = message.getDate();

  return {
    subject: truncate_(message.getSubject(), FIELD_LIMITS.subject) || '',
    sender: truncate_(message.getFrom(), FIELD_LIMITS.sender) || '',
    reply_to: truncate_(message.getReplyTo(), FIELD_LIMITS.reply_to),
    return_path: truncate_(message.getHeader('Return-Path'), FIELD_LIMITS.return_path),
    date: date ? date.toISOString() : null,
    auth_results: truncate_(message.getHeader('Authentication-Results'), FIELD_LIMITS.auth_results),
    links: extractLinksSafely_(message),
    attachments: safely_(extractAttachments_, message),
    body_text: safely_(extractBodyText_, message)
  };
}

/** Runs an optional extractor; on failure returns null ("not collected"), never "empty". */
function safely_(extractor, message) {
  try {
    return extractor(message);
  } catch (err) {
    console.error('Extraction failed: ' + (err && err.name));
    return null;
  }
}

/** Name, declared type and size only. Contents are never read or sent. */
function extractAttachments_(message) {
  return message.getAttachments({ includeInlineImages: false, includeAttachments: true })
    .slice(0, MAX_ATTACHMENTS)
    .map(function (attachment) {
      return {
        filename: truncate_(attachment.getName(), FIELD_LIMITS.attachment_name) || '(unnamed)',
        content_type: truncate_(attachment.getContentType(), FIELD_LIMITS.attachment_type),
        size: attachment.getSize()
      };
    });
}

/** Plain text with all web addresses replaced, whitespace collapsed, truncated. */
function extractBodyText_(message) {
  var text = String(message.getPlainBody() || '').substring(0, MAX_BODY_CHARS)
    .replace(/\bhttps?:\/\/[^\s<>"']{1,2000}/gi, '[link]')
    .replace(/\bwww\.[^\s<>"']{1,2000}/gi, '[link]')
    .replace(/\s+/g, ' ')
    .trim();
  return text.substring(0, FIELD_LIMITS.body_text);
}

/** null (not collected) on failure, so the backend never mistakes a failure for "no links". */
function extractLinksSafely_(message) {
  try {
    return extractLinks_(message);
  } catch (err) {
    console.error('Link extraction failed: ' + (err && err.name));
    return null;
  }
}

function extractLinks_(message) {
  var links = [];
  var seen = {};
  var match;

  // Anchors in the HTML body. Bounded quantifiers keep the regex linear on hostile input.
  var html = String(message.getBody() || '').substring(0, MAX_BODY_CHARS);
  var anchorRe = /<a\b[^>]{0,2000}?\bhref\s*=\s*(?:"([^"]{0,4000})"|'([^']{0,4000})'|([^\s>]{1,4000}))[^>]{0,2000}>([\s\S]{0,2000}?)<\/a>/gi;
  while (links.length < MAX_LINKS && (match = anchorRe.exec(html)) !== null) {
    addLink_(links, seen, decodeEntities_(match[1] || match[2] || match[3] || ''), linkText_(match[4]));
  }

  // Bare URLs in the plain-text body.
  var plain = String(message.getPlainBody() || '').substring(0, MAX_BODY_CHARS);
  var urlRe = /\bhttps?:\/\/[^\s<>"'()\[\]]{1,2000}/gi;
  while (links.length < MAX_LINKS && (match = urlRe.exec(plain)) !== null) {
    addLink_(links, seen, match[0], null);
  }
  return links;
}

function addLink_(links, seen, href, text) {
  var url = minimizeUrl_(href);
  if (!url) {
    return;
  }
  var key = url + '|' + (text || '');
  if (!seen[key]) {
    seen[key] = true;
    links.push({ url: url, text: text });
  }
}

/**
 * Keeps only scheme://[user@]host[:port]. Path, query and fragment often carry personal
 * tokens (password-reset links, tracking ids) and are never sent. A password in the
 * userinfo is dropped; the username is kept because it is the "@ trick" itself.
 */
function minimizeUrl_(href) {
  var m = /^\s*(https?):\/\/([^\/?#\\\s]*)/i.exec(href);
  if (!m || !m[2]) {
    return null;
  }
  var authority = m[2];
  var at = authority.lastIndexOf('@');
  if (at >= 0) {
    authority = authority.substring(0, at).split(':')[0] + '@' + authority.substring(at + 1);
  }
  return (m[1].toLowerCase() + '://' + authority).substring(0, FIELD_LIMITS.link_url);
}

/** Visible link text, but only when it is itself a URL or domain; otherwise nothing is sent. */
function linkText_(innerHtml) {
  var text = decodeEntities_(String(innerHtml || '').replace(/<[^>]{0,2000}>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
  var looksLikeAddress = /^(https?:\/\/)?[^\s\/@]+\.[^\s\/@]{2,}(\/\S*)?$/i.test(text);
  return looksLikeAddress ? text.substring(0, FIELD_LIMITS.link_text) : null;
}

function decodeEntities_(text) {
  return text
    .replace(/&#x([0-9a-f]{1,6});/gi, function (_, hex) { return safeCodePoint_(parseInt(hex, 16)); })
    .replace(/&#(\d{1,7});/g, function (_, dec) { return safeCodePoint_(parseInt(dec, 10)); })
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&');
}

function safeCodePoint_(code) {
  return code > 0 && code <= 0x10FFFF ? String.fromCodePoint(code) : '';
}

/** Returns null for empty values, otherwise the string cut to maxLength. */
function truncate_(value, maxLength) {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  var text = String(value);
  return text.length > maxLength ? text.substring(0, maxLength) : text;
}
