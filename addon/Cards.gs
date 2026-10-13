/**
 * CardService UI.
 *
 * Every string that comes from the email or the backend is escaped before
 * rendering: card text widgets interpret basic HTML, so an attacker-controlled
 * subject could otherwise inject formatting or fake UI elements.
 */

var ADDON_TITLE = 'Malicious Email Scorer';

function buildHomepageCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(ADDON_TITLE))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText('Open an email to analyze it.')))
    .build();
}

function buildResultCard(metadata, result) {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(ADDON_TITLE));

  card.addSection(CardService.newCardSection()
    .setHeader('Opened email')
    .addWidget(decorated_('Subject', metadata.subject || '(no subject)'))
    .addWidget(decorated_('From', metadata.sender || '(unknown)')));

  if (!result.ok) {
    card.addSection(CardService.newCardSection()
      .setHeader('Analysis unavailable')
      .addWidget(CardService.newTextParagraph().setText(escape_(result.error)))
      .addWidget(retryButton_()));
    return card.build();
  }

  var data = result.data;
  if (data.analysis_mode === 'connectivity_test') {
    card.addSection(buildConnectivitySection_(data));
  } else {
    card.addSection(buildVerdictSection_(data));
  }
  return card.build();
}

function buildConnectivitySection_(data) {
  var received = data.received || {};
  return CardService.newCardSection()
    .setHeader('Backend connectivity test')
    .addWidget(CardService.newTextParagraph()
      .setText('<b>This is NOT a security verdict.</b> ' + escape_(data.summary)))
    .addWidget(decorated_('Backend received subject length', String(received.subject_length)))
    .addWidget(decorated_('Sender domain (parsed by backend)', received.sender_domain || '(none)'))
    .addWidget(decorated_('Fields received', (received.fields_present || []).join(', ')))
    .addWidget(decorated_('Engine version', data.engine_version))
    .addWidget(retryButton_());
}

/** Placeholder for real verdicts; filled in when the detection engine lands. */
function buildVerdictSection_(data) {
  var section = CardService.newCardSection()
    .setHeader('Verdict: ' + escape_(data.verdict))
    .addWidget(decorated_('Score', data.score === null ? 'n/a' : String(data.score) + ' / 100'))
    .addWidget(CardService.newTextParagraph().setText(escape_(data.summary)));
  (data.findings || []).forEach(function (finding) {
    section.addWidget(decorated_(finding.title, finding.evidence));
  });
  return section;
}

function decorated_(label, value) {
  return CardService.newDecoratedText()
    .setTopLabel(escape_(label))
    .setText(escape_(value))
    .setWrapText(true);
}

function retryButton_() {
  return CardService.newTextButton()
    .setText('Analyze again')
    .setOnClickAction(CardService.newAction().setFunctionName('onRetry'));
}

function escape_(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
