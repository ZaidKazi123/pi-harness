/** Tool security copy. English is used for every locale until translations are added. */
export const toolSecurityEn = {
  navLabel: 'Tool security',
  navPlanner: 'Secure planner',
  sectionTitle: 'Tool security',
  sectionHint:
    'Review what add-on tools can do before they run, and decide which actions are allowed, asked or blocked.',
  plannerTitle: 'Secure planner (CaMeL)',
  plannerHint:
    'A planning mode where the model that decides what to do never sees file contents, web pages or tool results.',
  decision: { allow: 'Allow', ask: 'Ask', block: 'Block', inherit: 'Default ({value})' },
  risk: { low: 'Low risk', medium: 'Medium risk', high: 'High risk', critical: 'Critical' },
  status: {
    approved: 'Reviewed',
    unreviewed: 'Not reviewed',
    changed: 'Changed since review',
    blocked: 'Blocked'
  },
  verdict: {
    clean: 'No problems found',
    review: 'Needs your attention',
    dangerous: 'Signs of malicious behavior'
  },
  defaultsTitle: 'Default for each capability',
  defaultsHint:
    'Used for any tool that has the capability, unless you set something different for that package or tool.',
  unreviewedTools: 'Tools from packages you have not reviewed',
  requireReview: 'Review packages before installing',
  requireReviewHint: 'Installing from the app shows what the package can do first.',
  quarantineDangerous: 'Quarantine dangerous packages',
  quarantineDangerousHint:
    'Disable packages you have not reviewed when the scan finds signs of malicious behavior, so their code never loads.',
  quarantined: 'Quarantined: signs of malicious behavior',
  approveAndEnable: 'Approve and enable',
  blockInstallScripts: 'Block install scripts',
  blockInstallScriptsHint:
    'npm lifecycle scripts run only for packages you approved with scripts allowed.',
  provenanceTitle: 'Untrusted data',
  provenanceHint:
    'Track which text in a conversation came from files, web pages and tool results, and check actions that could send it off this computer. Applies in every permission mode, including full access.',
  provenanceEnabled: 'Track untrusted data in conversations',
  workspaceUntrusted: 'Treat project files as untrusted',
  workspaceUntrustedHint:
    'Files can contain instructions written by someone else, such as cloned repositories.',
  sinkWhenTainted: 'Network, push or publish after untrusted data was read',
  untrustedArgument: 'Network, push or publish using values taken from untrusted data',
  plannerToggle: 'Enable the secure planner',
  plannerToggleHint: 'Experimental. Uses your active model. Off by default.',
  packagesTitle: 'Installed tool packages',
  packagesEmpty: 'No third-party Pi packages are installed.',
  refresh: 'Rescan',
  approveCurrent: 'Approve current version',
  block: 'Block package',
  unblock: 'Unblock',
  packageDefaults: 'Package',
  tools: 'Tools',
  noTools: 'No tools detected',
  findings: 'Findings',
  findingsCount: '{count} finding | {count} findings',
  showFindings: 'Show findings',
  hideFindings: 'Hide findings',
  dependencies: 'Dependencies: {count} packages',
  hosts: 'Hosts referenced',
  envVars: 'Environment variables read',
  installScripts: 'Install scripts',
  digest: 'Code fingerprint',
  saved: 'Saved',
  loadFailed: 'Could not load tool security settings.',
  review: {
    title: 'Review {name}',
    scanning: 'Scanning the package. Nothing from it runs during review.',
    failed: 'This package could not be reviewed.',
    publisher: 'Publisher',
    version: 'Version',
    license: 'License',
    source: 'Source',
    canDo: 'This package can',
    nothing: 'No sensitive capabilities were detected.',
    undeclared: 'Not declared by the package',
    perTool: 'Tools in this package',
    decisionsHint:
      'Choose what happens before each capability is used. You can change this later in Settings → Tool security.',
    allowScripts: 'Allow install scripts',
    allowScriptsHint: 'Runs: {scripts}',
    acknowledge:
      'I understand this package shows signs of malicious behavior and want to install it anyway.',
    install: 'Install',
    update: 'Update',
    cancel: 'Cancel',
    truncated: 'The package was too large to scan completely.',
    filesScanned: '{count} files scanned'
  },
  planner: {
    disabled: 'The secure planner is off. Turn it on in Settings → Tool security.',
    folder: 'Workspace folder',
    chooseFolder: 'Choose folder',
    request: 'What should the planner do?',
    requestPlaceholder: 'For example: read notes.md and tell me the release date',
    plan: 'Create plan',
    run: 'Run plan',
    planning: 'Planning…',
    running: 'Running…',
    planTitle: 'Plan',
    planHint:
      'The planner only saw your request. Steps that read files or the web return untrusted data; only the quarantined model reads it.',
    steps: 'Steps',
    output: 'Result',
    trusted: 'From your request',
    untrusted: 'Untrusted: {sources}',
    status: {
      pending: 'Pending',
      running: 'Running',
      done: 'Done',
      blocked: 'Blocked',
      failed: 'Failed',
      skipped: 'Skipped'
    },
    extract: 'Quarantined extract',
    noFolder: 'Open a project first, or choose a folder.'
  }
} as const
