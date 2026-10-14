/**
 * CardService UI.
 *
 * Every string that comes from the email or the backend is escaped before
 * rendering: card text widgets interpret basic HTML, so an attacker-controlled
 * subject could otherwise inject formatting or fake UI elements.
 */

var ADDON_TITLE = 'Malicious Email Scorer';

var VERDICTS = {
  LOW_RISK: { label: 'Low risk', color: '#188038' },
  SUSPICIOUS: { label: 'Suspicious', color: '#e37400' },
  MALICIOUS: { label: 'Likely malicious', color: '#d93025' },
  INCONCLUSIVE: { label: 'Inconclusive', color: '#5f6368' }
};

var CHECK_STATUS_LABELS = {
  completed: 'Checked',
  not_applicable: 'Not applicable',
  not_available: 'Not enough data',
  failed: 'Check failed',
  not_implemented: 'Not analyzed yet'
};

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

  if (!result.ok) {
    card.addSection(buildEmailSection_(metadata));
    card.addSection(CardService.newCardSection()
      .setHeader('Analysis unavailable')
      .addWidget(CardService.newTextParagraph().setText(escape_(result.error)))
      .addWidget(retryButton_()));
    return card.build();
  }

  var data = result.data;
  if (data.analysis_mode !== 'live') {
    card.addSection(CardService.newCardSection()
      .setHeader('Analysis unavailable')
      .addWidget(CardService.newTextParagraph().setText('The backend returned an unsupported response version.'))
      .addWidget(retryButton_()));
    return card.build();
  }

  card.addSection(buildVerdictSection_(data));
  var reasons = buildReasonsSection_(data.findings || []);
  if (reasons) {
    card.addSection(reasons);
  }
  if ((data.positive_findings || []).length) {
    card.addSection(buildPositivesSection_(data.positive_findings));
  }
  card.addSection(buildCoverageSection_(data));
  card.addSection(buildEmailSection_(metadata));
  return card.build();
}

function buildVerdictSection_(data) {
  var verdict = VERDICTS[data.verdict] || VERDICTS.INCONCLUSIVE;
  var scoreText = data.score === null || data.score === undefined
    ? 'No score (not enough data)'
    : 'Risk score: ' + data.score + ' / 100';
  return CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText('<font color="' + verdict.color + '"><b>' + verdict.label + '</b></font>')
      .setBottomLabel(escape_(scoreText))
      .setWrapText(true))
    .addWidget(CardService.newTextParagraph().setText(escape_(data.summary)))
    .addWidget(CardService.newTextParagraph()
      .setText('<i>' + escape_(data.verdict_reason) + '</i>'))
    .addWidget(retryButton_());
}

/** Findings that contributed to the score, strongest first; others are listed as details. */
function buildReasonsSection_(findings) {
  var counted = findings.filter(function (f) { return f.counted_points > 0; });
  var context = findings.filter(function (f) { return f.counted_points === 0; });
  if (!counted.length && !context.length) {
    return null;
  }
  var section = CardService.newCardSection().setHeader('Why');
  counted.forEach(function (f) {
    var label = f.severity.toUpperCase() + ' · +' + f.counted_points + ' points';
    if (f.score_status !== 'counted' && f.note) {
      label += ' · ' + f.note;  // e.g. reinforcing or capped: explain the reduced points
    }
    section.addWidget(findingWidget_(f, label));
  });
  context.forEach(function (f) {
    section.addWidget(findingWidget_(f, 'Counted once · ' + (f.note || '')));
  });
  return section
    .setCollapsible(counted.length + context.length > 3)
    .setNumUncollapsibleWidgets(Math.min(counted.length, 3) || 1);
}

function findingWidget_(finding, topLabel) {
  return CardService.newDecoratedText()
    .setTopLabel(escape_(topLabel))
    .setText('<b>' + escape_(finding.title) + '</b><br>' + finding.evidence.map(escape_).join('<br>'))
    .setBottomLabel(escape_(finding.explanation))
    .setWrapText(true);
}

function buildPositivesSection_(positives) {
  var section = CardService.newCardSection().setHeader('Reassuring signs');
  positives.forEach(function (p) {
    section.addWidget(CardService.newDecoratedText()
      .setText(escape_(p.title))
      .setBottomLabel(escape_(p.explanation))
      .setWrapText(true));
  });
  return section;
}

/** Analysis completeness: what was checked and what was not - never implied safe. */
function buildCoverageSection_(data) {
  var coverage = data.coverage || { limitations: [] };
  var section = CardService.newCardSection()
    .setHeader('What was checked (' + coverage.checks_completed + ' of ' + coverage.checks_total + ')');
  (data.checks || []).forEach(function (c) {
    section.addWidget(CardService.newDecoratedText()
      .setText(escape_(c.title))
      .setBottomLabel(escape_(CHECK_STATUS_LABELS[c.status] || c.status))
      .setWrapText(true));
  });
  coverage.limitations.forEach(function (text) {
    section.addWidget(CardService.newTextParagraph().setText('<i>' + escape_(text) + '</i>'));
  });
  section.addWidget(CardService.newTextParagraph().setText(
    '<i>The risk score is a heuristic based on the signals above, not a probability. Engine ' +
    escape_(data.engine_version) + '.</i>'));
  return section.setCollapsible(true).setNumUncollapsibleWidgets(0);
}

function buildEmailSection_(metadata) {
  return CardService.newCardSection()
    .setHeader('Opened email')
    .addWidget(decorated_('Subject', metadata.subject || '(no subject)'))
    .addWidget(decorated_('From', metadata.sender || '(unknown)'))
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);
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
