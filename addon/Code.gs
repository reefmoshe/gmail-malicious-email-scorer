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

/**
 * "Explain with AI" button callback. The backend re-runs the deterministic engine on the
 * same message and only then adds the AI explanation, so the score and verdict shown are
 * always the engine's own. If the AI request fails, the deterministic result is shown again
 * with the rule-based explanation and a short note.
 */
function onExplainWithAi(e) {
  var metadata = extractMessageMetadata(e);
  var result = explainWithBackend(metadata);
  if (!result.ok) {
    result = analyzeWithBackend(metadata);  // deterministic result, template explanation
  }
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(
      buildResultCard(metadata, result, { explainRequested: true })))
    .build();
}

function buildAnalysisCard(e) {
  var metadata = extractMessageMetadata(e);
  var result = analyzeWithBackend(metadata);
  return buildResultCard(metadata, result, {});
}
