/**
 * Backend client.
 *
 * BACKEND_URL and API_KEY are read from Script Properties
 * (Project Settings -> Script properties), never hardcoded in source.
 * Always returns { ok: true, data } or { ok: false, error } - never throws,
 * so the UI can show a friendly error card.
 */

function analyzeWithBackend(metadata) {
  var props = PropertiesService.getScriptProperties();
  var baseUrl = props.getProperty('BACKEND_URL');
  var apiKey = props.getProperty('API_KEY');

  if (!baseUrl || !apiKey) {
    return { ok: false, error: 'Backend is not configured (BACKEND_URL / API_KEY script properties).' };
  }

  var response;
  try {
    response = UrlFetchApp.fetch(baseUrl.replace(/\/+$/, '') + '/analyze', {
      method: 'post',
      contentType: 'application/json',
      headers: { 'X-API-Key': apiKey },
      payload: JSON.stringify({ message: metadata }),
      muteHttpExceptions: true,
      followRedirects: false
    });
  } catch (err) {
    // Network failure or timeout - typically a free-tier backend waking up.
    console.error('Backend request failed: ' + err);
    return { ok: false, error: 'Could not reach the backend. It may be waking up - try again in ~30 seconds.' };
  }

  var status = response.getResponseCode();
  if (status !== 200) {
    console.error('Backend returned HTTP ' + status);
    return { ok: false, error: 'Backend returned HTTP ' + status + '.' };
  }

  try {
    return { ok: true, data: JSON.parse(response.getContentText()) };
  } catch (err) {
    return { ok: false, error: 'Backend returned an invalid response.' };
  }
}
