/**
 * Reads ONLY the currently opened message, using the short-lived access token
 * Gmail passes in the event object (scope: gmail.addons.current.message.readonly).
 *
 * Data minimization: only selected headers are extracted. No body, links or
 * attachments are read or sent to the backend at this stage.
 */

// Must match the max_length limits in backend/app/schemas.py.
var FIELD_LIMITS = {
  subject: 1000,
  sender: 500,
  reply_to: 500,
  return_path: 500,
  date: 100,
  auth_results: 5000
};

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
    auth_results: truncate_(message.getHeader('Authentication-Results'), FIELD_LIMITS.auth_results)
  };
}

/** Returns null for empty values, otherwise the string cut to maxLength. */
function truncate_(value, maxLength) {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  var text = String(value);
  return text.length > maxLength ? text.substring(0, maxLength) : text;
}
