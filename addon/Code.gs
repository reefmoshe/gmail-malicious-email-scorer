/**
 * Entry points declared in appsscript.json.
 *
 * Flow: Gmail opens a message -> onGmailMessageOpen -> extract minimal metadata
 * -> POST to backend -> render the result card.
 */

/** Homepage: shown when the add-on is opened without a message selected. */
function onHomepage(e) {
  return buildHomepageCard();
}

/** Contextual trigger: runs every time the user opens an email. */
function onGmailMessageOpen(e) {
  return buildAnalysisCard(e);
}

/** "Analyze again" button callback (e.g. after a backend cold start). */
function onRetry(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildAnalysisCard(e)))
    .build();
}

function buildAnalysisCard(e) {
  var metadata = extractMessageMetadata(e);
  var result = analyzeWithBackend(metadata);
  return buildResultCard(metadata, result);
}
