# Email alias migration strategy

Keep the primary mailbox private and use a unique alias per service when possible.

| Category | Pattern | Priority |
|---|---|---|
| banking | one stable alias per institution | highest; never recycle |
| shopping | unique per merchant | rotate after abuse |
| social | unique per platform | separates identity graphs |
| forums | unique per community | disposable only if recovery is unimportant |
| newsletters | one alias per sender or topic | easy bulk disable |
| services | unique per SaaS/vendor | supports breach attribution |
| temporary registrations | short-lived alias | never use for important recovery |

SimpleLogin and Addy.io can generate aliases that forward to an existing mailbox. Compare jurisdiction, custom-domain support, encryption, logs, recovery and pricing. Do not make the alias provider a single point of failure: export alias mappings, protect it with phishing-resistant 2FA and keep recovery codes offline.

Migration order: financial/recovery accounts, password manager, government/health, commerce, social, forums, newsletters. Update recovery addresses and verify login before retiring the old address. Never delete the primary mailbox until all recovery dependencies have been audited.
