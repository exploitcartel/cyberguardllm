"""Server-side translations for the whole app UI (English / Albanian).

Usage in templates: {{ t('key') }}
The active language is read from the 'lang' cookie (default 'en') and the
`t` function is registered as a Jinja global in webapp/app.py, so every
template that extends base.html can call it without importing anything.

This only translates UI chrome (labels, headers, buttons, static copy).
Actual data (target names, URLs, prompts, model responses, usernames,
activity log details) is never translated, since it is real content, not UI.
"""

TRANSLATIONS = {
    'pentest_rationale_note': {'en':'The rationale is AI-generated interpretation, not verified capability or policy evidence. The category definitions below come from the application.', 'al':'Arsyetimi është interpretim i gjeneruar nga AI, jo provë për aftësitë apo politikat. Përkufizimet e kategorive më poshtë vijnë nga aplikacioni.'},
    'coverage_limited': {'en':'Limited coverage', 'al':'Mbulim i kufizuar'},
    'coverage_limit_title': {'en':'Coverage limitation', 'al':'Kufizimi i mbulimit'},
    'coverage_verdict_help': {'en':'The verdict describes the observed replies. It does not certify unverified session continuity, resets or full multi-turn coverage.', 'al':'Verdikti përshkruan përgjigjet e vëzhguara. Ai nuk vërteton vazhdimësinë e paverifikuar të sesionit, rivendosjen apo mbulimin e plotë multi-turn.'},
    'benchmark_no_eligible': {'en':'No completed, fully evaluated assessments are available for this trend chart.', 'al':'Nuk ka vlerësime të përfunduara dhe plotësisht të vlerësuara për këtë grafik.'},
    'benchmark_unavailable': {'en':'Benchmark unavailable. Comparisons require completed, evaluated assessments without unresolved errors or review items. A score of zero alone is not evidence of safety.', 'al':'Benchmark i padisponueshëm. Krahasimi kërkon vlerësime të përfunduara pa gabime apo rezultate të pazgjidhura. Pikët zero nuk janë provë sigurie.'},
    'pentest_overhead': {'en':'Additional profiling requests / AI planning calls', 'al':'Kërkesa shtesë profilizimi / thirrje AI për planifikim'},
    'pentest_plan': {'en':'Assessment priority', 'al':'Prioriteti i vlerësimit'},
    'pentest_plan_details': {'en':'View saved plan', 'al':'Shiko planin e ruajtur'},
    'pentest_enable': {'en':'Run AI-PENTEST (requires configured AI API)', 'al':'Aktivizo AI-PENTEST (kërkon AI API të konfiguruar)'},
    'pentest_help': {'en':'Profile the target, build an AI-prioritized plan within your selected scope, run adaptive objective tests and replay candidate failures. Independent of AI-Powered and other engines.', 'al':'Profilizon objektivin, krijon plan me prioritetet e AI brenda kategorive që zgjedh, kryen teste adaptive dhe riprovon dështimet kandidate. I pavarur nga AI-Powered dhe modulet e tjera.'},
    'pentest_budget': {'en':'Maximum attack-generation attempts (8-40)', 'al':'Tentativat maksimale të gjenerimit të sulmeve (8-40)'},
    'pentest_limits': {'en':'Profiling and warm-up add two target requests; verification can add two replays per candidate failure. This is a bounded assessment agent, not unrestricted autonomous access. Set the authorized business policy on the Target. Hidden state, real data leaks and backend actions need independent evidence; a replay is not a clean session reset.', 'al':'Profilizimi dhe warm-up shtojnë dy kërkesa; verifikimi mund të shtojë dy riprovime për dështim kandidat. Agjenti ka kufij dhe scope të përcaktuar. Vendos politikën e autorizuar te Target. Rrjedhjet reale dhe veprimet në backend kërkojnë prova të pavarura; riprovimi nuk rivendos sesionin.'},
    'pentest_select_categories': {'en':'Select at least one category for AI-PENTEST.', 'al':'Zgjidh të paktën një kategori për AI-PENTEST.'},
    'ai_new_provider_key': {'en': 'The endpoint host changed. Use Change key and enter the new provider\'s key before saving.', 'al': 'Host-i i endpoint-it ndryshoi. Përdor Ndrysho çelësin dhe vendos çelësin e ofruesit të ri përpara ruajtjes.'},
    'ai_endpoint_invalid': {'en': 'Enter a valid HTTP or HTTPS API base URL without credentials, query or fragment.', 'al': 'Vendos URL të vlefshme HTTP ose HTTPS pa kredenciale, parametra query apo fragment.'},
    'nav_updates': {'en': 'Check for updates', 'al': 'Kontrollo përditësimet'},
    'updates_intro': {'en': 'Review and manage updates from the official repository.', 'al': 'Shiko dhe menaxho përditësimet nga repository zyrtar.'},
    'updates_installed': {'en': 'Installed version', 'al': 'Versioni i instaluar'},
    'updates_unknown': {'en': 'Unavailable', 'al': 'I padisponueshëm'},
    'updates_source': {'en': 'Source', 'al': 'Burimi'},
    'updates_dirty': {'en': 'This checkout has local changes.', 'al': 'Kjo kopje ka ndryshime lokale.'},
    'updates_available': {'en': 'Latest checked version', 'al': 'Versioni i fundit i kontrolluar'},
    'updates_commits': {'en': 'new commits', 'al': 'commits të reja'},
    'updates_ahead': {'en': 'local commits ahead', 'al': 'commits lokale përpara'},
    'updates_checked': {'en': 'Last check', 'al': 'Kontrolli i fundit'},
    'updates_not_checked': {'en': 'Check GitHub to compare versions. Nothing is downloaded automatically on page load.', 'al': 'Kontrollo GitHub për të krahasuar versionet. Hapja e faqes nuk shkarkon automatikisht përditësime.'},
    'updates_check': {'en': 'Check GitHub', 'al': 'Kontrollo GitHub'},
    'updates_admin': {'en': 'A Global Administrator can check and install updates.', 'al': 'Global Administrator mund të kontrollojë dhe instalojë përditësime.'},
    'updates_changes': {'en': 'Changes to review', 'al': 'Ndryshimet për shqyrtim'},
    'updates_no_changes': {'en': 'No new commits to display.', 'al': 'Nuk ka commits të reja për të shfaqur.'},
    'updates_install_help': {'en': 'Installation requires a clean main branch and no active scans. The updater backs up the database and keys, installs the checked commit, restarts the local server and checks startup. A failed startup triggers recovery to the saved version.', 'al': 'Instalimi kërkon degën main pa ndryshime lokale dhe pa skanime aktive. Ruhet kopje e databazës dhe çelësave, instalohet commit-i i kontrolluar dhe riniset serveri. Nëse nisja dështon, tentohet rikthimi te versioni i ruajtur.'},
    'updates_confirm': {'en': 'Install the checked update and restart the local server?', 'al': 'Ta instaloj përditësimin e kontrolluar dhe ta rinis serverin lokal?'},
    'updates_install': {'en': 'Install and restart', 'al': 'Instalo dhe rinis'},
    'updates_manual': {'en': 'Dependency changes and service-managed installations require a manual update. See setup instructions on', 'al': 'Ndryshimet e varësive dhe instalimet si shërbim kërkojnë përditësim manual. Shiko udhëzimet në'},
    'updates_status': {'en': 'Installation status', 'al': 'Gjendja e instalimit'},
    'updates_idle': {'en': 'No installation in progress.', 'al': 'Nuk ka instalim në proces.'},
    'updates_backup': {'en': 'Backup', 'al': 'Kopja rezervë'},
    'updates_history': {'en': 'Recent installations', 'al': 'Instalimet e fundit'},
    'ai_endpoint_preset': {'en': 'Endpoint preset', 'al': 'Zgjedhja e endpoint-it'},
    'ai_endpoint_help': {'en': 'Presets fill the API base URL. Enter a model ID available in your provider account and that provider\'s API key. Custom endpoints remain editable. Compatibility depends on the endpoint supporting Chat Completions.', 'al': 'Zgjedhja plotëson URL-në e API-së. Vendos ID-në e modelit që ke në llogarinë e ofruesit dhe çelësin e tij API. Endpoint-et mund të ndryshohen manualisht dhe duhet të mbështesin Chat Completions.'},
    'ai_endpoint_custom': {'en': 'Custom / other compatible endpoint', 'al': 'Endpoint tjetër i përputhshëm'},
    'ai_model_required': {'en': 'Enter the model ID for this endpoint before saving.', 'al': 'Vendos ID-në e modelit për këtë endpoint përpara ruajtjes.'},
    # ---- base.html / sidebar ----
    "theme_light": {"en": "Light", "al": "E çelur"},
    "theme_dark": {"en": "Dark", "al": "E errët"},
    "brand_sub": {"en": "AI Security Assessment", "al": "Vlerësim Sigurie AI"},
    "nav_dashboard": {"en": "Dashboard", "al": "Paneli"},
    "nav_targets": {"en": "Targets", "al": "Objektivat"},
    "nav_scan_configs": {"en": "Scan Configs", "al": "Konfigurime Skanimi"},
    "nav_tasks": {"en": "Tasks", "al": "Detyrat"},
    "nav_results": {"en": "Results", "al": "Rezultatet"},
    "nav_rules": {"en": "Rules Library", "al": "Libraria e Rregullave"},
    "nav_activity": {"en": "Activity Log", "al": "Regjistri i Aktivitetit"},
    "nav_settings": {"en": "Settings", "al": "Cilësimet"},
    "logout": {"en": "Logout", "al": "Dilni"},
    "built_by": {"en": "Built by", "al": "Ndërtuar nga"},

    # ---- dashboard.html ----
    "dashboard_title": {"en": "Dashboard", "al": "Paneli"},
    "dashboard_sub": {"en": "Overview of your LLM security assessments", "al": "Përmbledhje e vlerësimeve të sigurisë LLM"},
    "total_scans": {"en": "Total Scans", "al": "Skanime Gjithsej"},
    "total_targets": {"en": "Total Targets", "al": "Objektiva Gjithsej"},
    "high_critical": {"en": "High / Critical", "al": "Të Larta / Kritike"},
    "avg_risk_score": {"en": "Avg Risk Score", "al": "Risku Mesatar"},
    "findings_by_severity": {"en": "Findings by severity", "al": "Gjetjet sipas ashpërsisë"},
    "owasp_coverage": {"en": "OWASP LLM Top 10 coverage", "al": "Mbulimi OWASP LLM Top 10"},
    "recent_scans": {"en": "Recent scans", "al": "Skanimet e fundit"},
    "col_date": {"en": "Date", "al": "Data"},
    "col_target": {"en": "Target", "al": "Objektivi"},
    "col_findings": {"en": "Findings", "al": "Gjetje"},
    "col_risk_score": {"en": "Risk Score", "al": "Risku"},
    "col_status": {"en": "Status", "al": "Statusi"},
    "no_scans_yet": {"en": "No scans yet. Add a target and run your first scan.", "al": "Ende s'ka skanime. Shto një objektiv dhe nis skanimin e parë."},

    # ---- targets.html ----
    "targets_title": {"en": "Targets", "al": "Objektivat"},
    "targets_sub": {"en": "Manage your LLM targets and auto-discovery profiles", "al": "Menaxho objektivat LLM dhe profilet e zbulimit automatik"},
    "add_target": {"en": "+ Add Target", "al": "+ Shto Objektiv"},
    "col_name": {"en": "Name", "al": "Emri"},
    "col_url": {"en": "URL", "al": "URL"},
    "col_auth": {"en": "Auth", "al": "Autentikimi"},
    "col_format": {"en": "Format", "al": "Formati"},
    "col_actions": {"en": "Actions", "al": "Veprime"},
    "btn_delete": {"en": "Delete", "al": "Fshi"},
    "view_only": {"en": "view only", "al": "vetëm shikim"},
    "no_targets_yet": {"en": 'No targets yet. Add one with "+ Add Target".', "al": 'Ende s\'ke objektiv. Shto një me "+ Shto Objektiv".'},
    "business_context_label": {"en": "Business context:", "al": "Konteksti i biznesit:"},
    "business_context_placeholder": {"en": "e.g. banking support bot that can authorize transfers",
                                      "al": "p.sh. bot support banke qe mund te autorizoje transferta"},

    # ---- target_new.html ----
    "add_target_title": {"en": "Add Target", "al": "Shto Objektiv"},
    "add_target_sub": {"en": "Enter the URL and token. We will auto-detect the auth scheme, body format and response field.",
                        "al": "Fut URL-në dhe token-in. Do zbulojmë vetë auth scheme, body format dhe response field."},
    "field_target_name": {"en": "Target name", "al": "Emri i objektivit"},
    "field_target_url": {"en": "Target URL", "al": "URL e objektivit"},
    "recommendation_title": {"en": "Recommendation", "al": "Rekomandimi"},
    "btn_back": {"en": "Back", "al": "Kthehu"},
    "optional": {"en": "optional", "al": "opsionale"},
    "field_session_token": {"en": "Session Token", "al": "Token Sesioni"},
    "btn_detect": {"en": "Detect", "al": "Zbulo"},
    "btn_cancel": {"en": "Cancel", "al": "Anulo"},
    "discovery_results": {"en": "Discovery Results", "al": "Rezultatet e Zbulimit"},
    "auth_scheme_label": {"en": "Auth Scheme:", "al": "Auth Scheme:"},
    "body_format_label": {"en": "Body Format:", "al": "Body Format:"},
    "response_field_label": {"en": "Response Field:", "al": "Response Field:"},
    "btn_save_target": {"en": "Save Target", "al": "Ruaj Objektivin"},

    # ---- target_edit.html ----
    "edit_target_title": {"en": "Edit Target", "al": "Ndrysho Objektivin"},
    "edit_target_sub": {"en": "Change the name, URL, auth scheme, body format, or session token. Leave the token blank to keep the current one.",
                         "al": "Ndrysho emrin, URL-ne, auth scheme, body format, ose token-in e sesionit. Lere token-in bosh per ta mbajtur ate ekzistuesin."},
    "field_auth_scheme": {"en": "Auth Scheme", "al": "Auth Scheme"},
    "field_body_format": {"en": "Body Format", "al": "Body Format"},
    "field_body_encoding": {"en": "Body Encoding", "al": "Body Encoding"},
    "field_response_field": {"en": "Response Field", "al": "Response Field"},
    "field_new_token_optional": {"en": "New Session Token (optional)", "al": "Token Sesioni i Ri (opsionale)"},
    "token_blank_hint": {"en": "Leave blank to keep the current token.", "al": "Lere bosh per ta mbajtur token-in aktual."},
    "btn_save_changes": {"en": "Save Changes", "al": "Ruaj Ndryshimet"},
    "btn_edit": {"en": "Edit", "al": "Ndrysho"},
    "discovery_failed": {"en": "Discovery failed. Check the URL/token, or set the format manually (v2).",
                          "al": "Zbulimi dështoi. Kontrollo URL-në/token-in, ose vendos formatin manualisht (v2)."},
    "browser_discovery_title": {"en": "Browser-Assisted Discovery", "al": "Zbulim me Ndihmen e Browser-it"},
    "browser_discovery_explanation": {
        "en": "Don't know the chatbot's API endpoint yet? Give the page URL instead. A headless browser opens the page, types a test message into whatever looks like the chat input, sends it, and watches the network traffic to find the real backend API call automatically, the same way you would in DevTools, but without doing it by hand.",
        "al": "S'e di akoma API endpoint e chatbot-it? Jep URL-ne e faqes ne vend te tij. Nje browser headless e hap faqen, shkruan nje mesazh test ne cfaredo qe duket si chat input, e dergon, dhe veshtron trafikun e rrjetit per te gjetur vete API-ne reale te backend-it, njelloj si do benit ne DevTools, por pa e bere me dore.",
    },
    "field_page_url": {"en": "Page URL (not the API)", "al": "URL e faqes (jo API-ja)"},
    "field_test_message": {"en": "Test message to send", "al": "Mesazhi test per te dergu"},
    "btn_run_browser_discovery": {"en": "Discover via Browser", "al": "Zbulo permes Browser-it"},
    "browser_discovery_results": {"en": "Captured Automatically", "al": "Kapur Automatikisht"},
    "captured_url_label": {"en": "Captured API URL:", "al": "API URL e kapur:"},
    "review_token_hint": {"en": "Review the captured token/cookie before saving, it may need to be refreshed if the page session has since expired.",
                           "al": "Shiko token-in/cookie-n e kapur para se ta ruash, mund te nevojitet te rifreskohet nese sesioni i faqes ka skaduar."},

    "ws_discovery_title": {"en": "WebSocket Discovery", "al": "Zbulim WebSocket"},
    "ws_discovery_explanation": {
        "en": "For a chatbot backend that talks over a raw WebSocket (ws:// or wss://) instead of normal HTTP, not Socket.io (use the panel below for that). Give the ws:// URL and the token if there is one. This tries combinations of auth placement (header, URL query, first-message) and body shape automatically, the same way HTTP discovery does. You can tell a target is raw WebSocket if your browser's DevTools Network tab shows the connection with protocol 'WS', not 'HTTP'.",
        "al": "Per nje backend chatbot-i qe flet permes WebSocket te thjeshte (ws:// ose wss://) ne vend te HTTP normal, jo Socket.io (perdor panelin me poshte per ate). Jep URL-ne ws:// dhe token-in nese ka. Kjo provon vete kombinime te vendit te auth (header, query ne URL, mesazh i pare) dhe forma te body, njelloj si zbulimi HTTP. E njef se objektivi eshte WebSocket i thjeshte nese tab-i Network ne DevTools te browser-it tregon lidhjen me protokoll 'WS', jo 'HTTP'.",
    },
    "field_ws_url": {"en": "WebSocket URL (ws:// or wss://)", "al": "URL WebSocket (ws:// ose wss://)"},
    "btn_run_ws_discovery": {"en": "Discover via WebSocket", "al": "Zbulo permes WebSocket"},
    "ws_auth_mode_label": {"en": "Auth Mode:", "al": "Menyra e Auth:"},

    "socketio_discovery_title": {"en": "Socket.io Discovery", "al": "Zbulim Socket.io"},
    "socketio_discovery_explanation": {
        "en": "For a chat widget built on Socket.io, the event-based protocol many SaaS chat widgets use. Give the page's http(s):// URL, NOT a ws:// URL, Socket.io negotiates its own connection. Socket.io has no standard event name, so this tries a short list of common patterns (message, chat message, send_message, and similar); it may need manual adjustment for an unusual backend, that is a property of Socket.io itself, not a shortcut taken here.",
        "al": "Per nje chat widget te ndertuar me Socket.io, protokolli i bazuar ne events qe shume chat widget SaaS e perdorin. Jep URL-ne http(s):// te faqes, JO nje URL ws://, Socket.io negocion vete lidhjen e saj. Socket.io s'ka emer standard eventi, keshtu kjo provon nje liste te shkurter modelesh te zakonshem (message, chat message, send_message, etj); mund te duhet rregullim manual per nje backend te pazakonshem, kjo eshte nje veti e vete Socket.io, jo nje mangesi e tool-it.",
    },
    "field_socketio_url": {"en": "Page URL (http:// or https://, not ws://)", "al": "URL i faqes (http:// ose https://, jo ws://)"},
    "btn_run_socketio_discovery": {"en": "Discover via Socket.io", "al": "Zbulo permes Socket.io"},
    "ws_event_name_label": {"en": "Event Name:", "al": "Emri i Event-it:"},

    # ---- scan_configs.html ----
    "scan_configs_title": {"en": "Scan Configs", "al": "Konfigurime Skanimi"},
    "scan_configs_sub": {"en": "Build combinations of OWASP categories to run scans against",
                          "al": "Krijo kombinime kategorish OWASP për skanime"},
    "new_config": {"en": "New config", "al": "Konfigurim i ri"},
    "config_name_label": {"en": "Config name", "al": "Emri i konfigurimit"},
    "owasp_categories_label": {"en": "OWASP Categories", "al": "Kategoritë OWASP"},
    "ai_powered_checkbox_label": {"en": "AI-Powered mode for this config (uses the AI attacking agent instead of static payloads, requires AI API set up in Settings)",
                                   "al": "Modaliteti AI-Powered për këtë konfigurim (përdor AI agent sulmues në vend të payload-ve statikë, kërkon AI API të konfiguruar te Settings)"},
    "ai_campaign_execution": {"en": "AI campaign execution", "al": "Ekzekutimi i fushatës AI"},
    "ai_campaign_generation": {"en": "Generations / ceiling", "al": "Gjenerime / kufiri"},
    "ai_campaign_target_calls": {"en": "Target requests", "al": "Kërkesa ndaj targetit"},
    "ai_campaign_replays": {"en": "Retest requests", "al": "Kërkesa ritestimi"},
    "ai_campaign_judge_calls": {"en": "Judge calls", "al": "Thirrje gjykimi"},
    "ai_campaign_count_note": {"en": "These are call counts, not token usage or billing. Warmup is counted separately.", "al": "Këto janë numra thirrjesh, jo konsum tokenash apo faturim. Ngrohja numërohet veçmas."},
    "ai_campaign_warmup": {"en": "Warmup requests", "al": "Kërkesa ngrohjeje"},
    "ai_campaign_progress": {"en": "Objective progress", "al": "Progresi i objektivit"},
    "ai_freestyle_explanation": {
        "en": "Objective campaign: two focused objectives per category share a fixed generation budget. The attacker uses prior results and optional recon, avoids duplicate prompts, and follows quoted evidence of progress. A confirmed objective stops; the other objective continues. Put the target's permitted actions and policy limits in its Business Context. Unverified leaks or backend actions require REVIEW.",
        "al": "Fushatë me objektiva: dy objektiva për kategori ndajnë një buxhet fiks gjenerimi. Sulmuesi përdor rezultatet e mëparshme dhe recon opsional, shmang promptet e përsëritura dhe ndjek prova konkrete progresi. Ndalon objektivin e konfirmuar dhe vazhdon tjetrin. Te Business Context vendos veprimet e lejuara dhe kufijtë e politikës së targetit. Rrjedhjet apo veprimet në backend pa prova të pavarura kërkojnë REVIEW."},
    "field_ai_max_attempts": {"en": "Max attempts per category", "al": "Max provat per kategori"},
    "field_ai_intensity": {"en": "AI-Powered Intensity", "al": "Intensiteti i AI-Powered"},
    "ai_intensity_test_label": {"en": "Test", "al": "Test"},
    "ai_intensity_test_tip": {"en": "8 attempts per category, fixed. A quick sanity check that the pipeline itself works end to end - not a real security assessment. Never extended.",
                               "al": "8 prova per kategori, fikse. Nje test i shpejte qe mekanizmi funksionon fund-e-fund - jo nje vleresim real sigurie. Nuk zgjatet kurre."},
    "ai_intensity_low_label": {"en": "Low", "al": "Low"},
    "ai_intensity_low_tip": {"en": "Up to 10 generated attempts per category, shared across its objectives. Never extended because of judge uncertainty.",
                              "al": "Deri 10 tentativa të gjeneruara për kategori, të ndara mes objektivave. Pasiguria e gjykuesit nuk e zgjat buxhetin."},
    "ai_intensity_medium_label": {"en": "Medium", "al": "Medium"},
    "ai_intensity_medium_tip": {"en": "Up to 15 attempts per category. More room to adapt the attack before giving up on a category.",
                                 "al": "Deri 15 prova per kategori. Me shume hapesire per te adaptuar sulmin para se te heqe dore nga nje kategori."},
    "ai_intensity_high_label": {"en": "High", "al": "High"},
    "ai_intensity_high_tip": {"en": "Up to 20 attempts per category. A thorough pass, meant for a target you expect to take longer to crack if it's vulnerable at all.",
                               "al": "Deri 20 prova per kategori. Nje kalim i thelle, per nje target qe mendon se do marre me kohe per t'u thyer nese eshte i dobet fare."},
    "ai_intensity_aggressive_label": {"en": "Aggressive", "al": "Aggressive"},
    "ai_intensity_aggressive_tip": {"en": "Up to 30 attempts per category. The most thorough pass - every category gets the most room to try different angles before being marked resistant.",
                                     "al": "Deri 30 prova per kategori. Kalimi me i thelle - cdo kategori merr me shume hapesire per te provuar kende te ndryshme sulmi para se te shenohet rezistente."},
    "ai_intensity_shared_tip": {"en": "Generation ceiling shared by the category's objectives. Duplicate prompts are not sent. Enabled retests add target/judge calls, not new generated attacks. Judge confidence and objective progress are separate measurements.",
                                "al": "Kufiri i gjenerimit ndahet mes objektivave të kategorisë. Promptet e përsëritura nuk dërgohen. Ritestimet shtojnë thirrje ndaj targetit/gjykuesit, jo sulme të reja të gjeneruara. Confidence dhe progresi i objektivit janë matje të ndryshme."},
    "enable_fingerprint_checkbox": {"en": "Guardrail fingerprinting (offline, no AI needed)",
                                     "al": "Fingerprint i guardrail-it (offline, pa AI)"},
    "fingerprint_explanation": {
        "en": "Sends one generic jailbreak probe and matches the refusal phrasing against known guardrail/"
              "moderation styles (OpenAI-style, Anthropic-style, Llama-Guard-style, cloud content filters, etc). "
              "Purely informational, not a vulnerability by itself, helps pick which follow-up techniques are "
              "likely to work against this target.",
        "al": "Dergon nje probe gjenerik jailbreak dhe krahason frazen e refuzimit me stile te njohura guardrail/"
              "moderation (OpenAI-style, Anthropic-style, Llama-Guard-style, cloud content filters, etj). Thjesht "
              "informativ, jo dobesi ne vetvete, ndihmon te zgjedhesh cilat teknika pasuese kane me shume gjase "
              "te funksionojne kunder ketij target-i."},
    "btn_trend": {"en": "Trend", "al": "Trend"},
    "trend_title": {"en": "Risk Score Trend", "al": "Trendi i Risk Score"},
    "trend_sub": {"en": "How this target's risk score has changed across every completed scan.",
                  "al": "Si eshte ndryshuar risk score i ketij target-i ndermjet cdo skanimi te perfunduar."},
    "trend_history": {"en": "Scan history", "al": "Historia e skanimeve"},
    "benchmark_title": {"en": "Benchmark comparison", "al": "Krahasim benchmark"},
    "benchmark_target_avg": {"en": "This target's average risk score", "al": "Risk score mesatar i ketij target-i"},
    "benchmark_global_avg": {"en": "Average across all scanned targets", "al": "Mesatarja ne te gjithe target-et e skanuar"},
    "benchmark_above": {"en": "This target is riskier than the average target scanned with this tool",
                         "al": "Ky target eshte me i rrezikuar se mesatarja e target-eve te skanuar me kete tool"},
    "benchmark_below": {"en": "This target is less risky than the average target scanned with this tool",
                         "al": "Ky target eshte me pak i rrezikuar se mesatarja e target-eve te skanuar me kete tool"},
    "benchmark_typical": {"en": "This target is roughly in line with the average target scanned with this tool",
                          "al": "Ky target eshte afersisht ne nivel me mesataren e target-eve te skanuar me kete tool"},
    "enable_session_isolation_checkbox": {"en": "Session isolation check (offline, no AI needed)",
                                           "al": "Kontroll i izolimit te session-it (offline, pa AI)"},
    "session_isolation_explanation": {
        "en": "Plants a secret in one prompt, then probes with a second prompt deliberately phrased as a fresh, "
              "unrelated question that replays no conversation history. If the secret still comes back, the "
              "target is relying on hidden session state across what should be independent requests, the same "
              "kind of implicit state that causes real cross-user data bleed in production. One credential only, "
              "so this cannot prove two different end-users would see each other's data, but it is the "
              "precondition for that class of bug (LLM02).",
        "al": "Mbjell nje sekret ne nje prompt, pastaj provon me nje prompt te dyte te formuluar qellimisht si "
              "pyetje e re e palidhur, pa riperseritur historine e bisedes. Nese sekreti kthehet perseri, target-i "
              "po mbeshtetet ne state te fshehur sessioni ndermjet kerkesave qe duhet te jene te pavarura, e njejta "
              "lloj state e fshehur qe shkakton rrjedhje te dhenash mes perdoruesve ne production. Vetem nje "
              "kredencial eshte ne dispozicion, pra kjo nuk provon qe dy perdorues te ndryshem do shikonin te "
              "dhenat e njeri-tjetrit, por eshte parakushti per ate lloj problemi (LLM02)."},
    "btn_save_config": {"en": "Save Configuration", "al": "Ruaj Konfigurimin"},
    "existing_configs": {"en": "Existing configs", "al": "Konfigurime ekzistuese"},
    "use_garak_checkbox_label": {"en": "Run Garak module (external, NVIDIA's garak) - offline, no AI API needed",
                                  "al": "Ekzekuto modulin Garak (i jashtëm, garak nga NVIDIA) - offline, s'ka nevojë për AI API"},
    "garak_module_explanation": {
        "en": "Runs a curated set of garak's own probes directly against this target through its real auth/body "
              "config - a fully standalone test, independent of the static payload scan above (turn that off "
              "if you want garak only). No AI API configured under Settings: runs purely offline on garak's own "
              "heuristic/substring detectors, exactly like running garak by itself. AI API configured: each "
              "result is additionally cross-checked by this tool's own AI judge, and only kept as a finding when "
              "both agree (a disagreement is flagged REVIEW instead of trusted either way) - this is optional, "
              "not required, and never blocks garak from running without it. Requires garak installed "
              "(pip install -r requirements.txt).",
        "al": "Ekzekuton një grup të zgjedhur prob-esh nga vet garak direkt kundrejt këtij targeti, duke "
              "përdorur auth/body config-un real të tij - test krejtësisht i pavarur, pa lidhje me skanimin "
              "statik më sipër (fike atë nëse don vetëm garak). Pa AI API të konfiguruar te Settings: run "
              "tërësisht offline me detektorët heuristikë/substring të vetë garak, njësoj si ta ekzekutosh garak "
              "vetë. Me AI API të konfiguruar: çdo rezultat kontrollohet shtesë nga gjykatësi AI i vetë mjetit, "
              "dhe mbahet si gjetje vetëm kur pajtohen të dy (mospajtimi shënohet REVIEW në vend që t'i besohet "
              "njërit anash) - kjo është opsionale, jo e detyrueshme, dhe asnjëherë s'e pengon garak të punojë "
              "pa të. Kërkon garak të instaluar (pip install -r requirements.txt)."},
    "garak_extra_probes_label": {"en": "Advanced: extra garak probe names (comma-separated, any installed probe)",
                                  "al": "Të përparuara: emra shtesë probe-sh garak (ndarë me presje, çdo probe i instaluar)"},
    "section_crescendo": {"en": "Multi-turn Attack (Crescendo)", "al": "Sulm Multi-turn (Crescendo)"},
    "use_crescendo_label": {"en": "Run built-in Crescendo multi-turn attack - requires AI API",
                             "al": "Ekzekuto sulmin multi-turn Crescendo (i brendshëm) - kërkon AI API"},
    "needs_ai_api": {"en": "needs AI API", "al": "kërkon AI API"},
    "crescendo_explanation": {
        "en": "An attacking model holds a real conversation with the target: it starts innocuous and on-topic, then "
              "escalates in small steps that build on the target's own replies, and backs off and changes angle when "
              "the target refuses. A judge reads every reply. This finds guardrails that hold against a single "
              "request but give way gradually, which a fixed prompt list cannot. Objectives test policy and "
              "business-logic boundaries only. Needs the AI API under Settings.",
        "al": "Një model sulmues bën një bisedë të vërtetë me objektivin: nis i pafajshëm dhe në temë, pastaj "
              "përshkallëzon me hapa të vegjël mbi përgjigjet e vetë objektivit, dhe tërhiqet e ndryshon kënd kur "
              "ai refuzon. Një gjyqtar lexon çdo përgjigje. Gjen mbrojtje që qëndrojnë ndaj një kërkese të vetme "
              "por lëshojnë gradualisht. Objektivat testojnë vetëm kufijtë e politikave dhe të logjikës së biznesit. "
              "Kërkon AI API te Settings."},
    "crescendo_turns_label": {"en": "Max turns per objective", "al": "Maks. kthesa për objektiv"},
    "use_pyrit_checkbox_label": {"en": "Run PyRIT module (external, Microsoft PyRIT) - requires AI API",
                                  "al": "Ekzekuto modulin PyRIT (i jashtëm, Microsoft PyRIT) - kërkon AI API"},
    "pyrit_module_explanation": {
        "en": "Runs Microsoft PyRIT's adaptive multi-turn attack (Crescendo) directly against this target for "
              "the selected objectives - a fully standalone test, independent of the static payload scan above "
              "(turn that off if you want PyRIT only). The AI API requirement is not something this app adds: "
              "Crescendo is an LLM that decides each next message by reading the target's previous reply, and "
              "the resulting conversation is judged by an LLM too, so a real model is unavoidable for this "
              "specific technique, the same as using PyRIT directly. Requires PyRIT installed AND an AI API "
              "key configured under Settings.",
        "al": "Ekzekuton sulmin adaptiv shumë-turnor të Microsoft PyRIT (Crescendo) direkt kundrejt këtij "
              "targeti për objektivat e zgjedhur - test krejtësisht i pavarur, pa lidhje me skanimin statik "
              "më sipër (fike atë nëse don vetëm PyRIT). Kërkesa për AI API s'është diçka që e shtojmë ne: "
              "Crescendo është vetë një AI që vendos çdo mesazh të radhës duke lexuar përgjigjen e mëparshme të "
              "targetit, dhe biseda që del gjykohet gjithashtu nga një AI, pra një model real është i "
              "pashmangshëm për këtë teknikë specifike, njësoj si kur e përdor PyRIT direkt vetë. Kërkon PyRIT "
              "të instaluar DHE një AI API key të konfiguruar te Settings."},
    "tool_not_installed": {"en": "not installed", "al": "s'është instaluar"},
    "enable_retest_checkbox": {"en": "Retest FAIL findings for reproducibility",
                                "al": "Rifirmo gjetjet FAIL për reproducibility"},
    "retest_explanation": {
        "en": "LLMs are non-deterministic: the same prompt can fail once and pass the next time. When enabled, "
              "every FAIL finding is resent the number of times below and reported with a reproducibility rate "
              "(e.g. 2/3), instead of being treated as certain from a single attempt.",
        "al": "LLM-të janë jo-deterministike: i njëjti prompt mund të dështojë një herë dhe të kalojë herën "
              "tjetër. Kur aktivizohet, çdo gjetje FAIL ridërgohet sa herë tregohet poshtë dhe raportohet me një "
              "shkallë reproducibility (p.sh. 2/3), në vend që të trajtohet si e sigurt nga një provë e vetme."},
    "field_retest_count": {"en": "Total attempts per FAIL (including the first)", "al": "Përpjekje gjithsej për FAIL (duke përfshirë të parën)"},
    "mutations_label": {"en": "Payload mutation engine (advanced)", "al": "Motori i mutacioneve të payload-it (i avancuar)"},
    "mutations_explanation": {
        "en": "For each selected technique, every single-prompt rule in the library is also sent in an "
              "obfuscated form, to test whether a target that blocks the plain-text attack still blocks a "
              "disguised one. This multiplies scan time by roughly (1 + number of techniques selected).",
        "al": "Për çdo teknikë të zgjedhur, çdo rregull single-prompt në librari dërgohet gjithashtu në formë të "
              "fshehur, për të testuar nëse një target që blokon sulmin në tekst të thjeshtë e blokon edhe atë të "
              "fshehur. Kjo e shumëzon kohën e skanimit afërsisht me (1 + numri i teknikave të zgjedhura)."},
    "enable_canary_checkbox": {"en": "Run out-of-band canary checks (LLM03, needs canary_base_url in Settings)",
                                "al": "Ekzekuto kontrolle canary jashtë-brezi (LLM03, kërkon canary_base_url te Settings)"},
    "canary_scan_explanation": {
        "en": "Proves, instead of just claiming, whether the target actually performs an unauthorized outbound "
              "action (fetching a URL), by giving it a unique one-time URL and checking server-side whether it "
              "was really requested. Only works if the target can actually reach this app over the network.",
        "al": "Provon, jo thjesht pretendon, nëse targeti kryen realisht një veprim të paautorizuar jashtë (marrjen "
              "e një URL), duke i dhënë një URL unike njëpërdorimshe dhe duke kontrolluar nga ana e serverit nëse "
              "u kërkua realisht. Funksionon vetëm nëse targeti mund ta arrijë realisht këtë app nëpër rrjet."},

    "enable_recon_checkbox": {"en": "AI recon: extract system prompt and generate personalized payloads (LLM08)",
                               "al": "AI recon: nxjerr system prompt-in dhe gjeneron payload personalizuar (LLM08)"},
    "recon_explanation": {
        "en": "Before scoring findings normally, this probes the target for its own system prompt / hidden "
              "instructions. If it extracts something credible, and an AI API is configured in Settings, it asks "
              "that AI to write attack prompts personalized to this target's own persona and domain for the "
              "selected categories, instead of only generic canned payloads. Without an AI API configured, this "
              "still runs the leak probes (with a simpler heuristic check) but skips personalization.",
        "al": "Para vlerësimit normal të gjetjeve, kjo provon target-in për system prompt-in/instruksionet e tij "
              "të fshehura. Nëse nxjerr dicka te besueshme, dhe ka AI API të konfiguruar te Settings, i kërkon "
              "atij AI të shkruajë payload sulmi të personalizuar sipas personazhit/domain-it të vetë target-it "
              "për kategoritë e zgjedhura, jo vetëm payload gjenerik. Pa AI API, xhiron prapë probe-t e leakage "
              "(me kontroll heuristik më të thjeshtë) por anashkalon personalizimin."},

    "attack_chains_title": {"en": "Attack Chain Analysis", "al": "Analiza e Zinxhirit te Sulmit"},
    "attack_chains_explanation": {
        "en": "Cases where two or more of this scan's findings could realistically be combined into a single, "
              "more damaging attack path, like a chain in a traditional penetration test report.",
        "al": "Raste ku dy ose me shume gjetje te ketij skanimi mund te kombinohen realisht ne nje zinxhir sulmi "
              "me te demshem, njelloj si nje chain ne nje raport pentest tradicional."},
    "chain_static_badge": {"en": "General pairing", "al": "Kombinim gjenerik"},
    "chain_static_hint": {"en": "Based on OWASP category pairing, not written from these specific findings",
                           "al": "Bazuar ne kombinim kategorie OWASP, jo shkruar nga keto gjetje specifike"},
    "chain_ai_badge": {"en": "AI analysis", "al": "Analize AI"},
    "canary_title": {"en": "Out-of-band canary (LLM03)", "al": "Canary jashtë-brezi (LLM03)"},
    "canary_explanation": {
        "en": "Base URL this app is reachable at FROM the target you are testing (not necessarily from this "
              "machine's own localhost), used by the canary module to build unique one-time URLs. Leave blank to "
              "skip canary checks. Example: http://203.0.113.10:8000 or a tunnel URL if the target is elsewhere.",
        "al": "URL-ja bazë ku ky app arrihet NGA targeti që po teston (jo domosdoshmërisht nga localhost i vetë "
              "këtij makinerie), përdorur nga moduli canary për të ndërtuar URL unike njëpërdorimshe. Lëre bosh "
              "për ta anashkaluar. Shembull: http://203.0.113.10:8000 ose një URL tuneli nëse targeti është diku "
              "tjetër."},
    "field_canary_base_url": {"en": "Canary base URL", "al": "URL-ja bazë e canary"},
    "btn_save_canary": {"en": "Save Canary Settings", "al": "Ruaj Settings e Canary"},
    "reproducibility_hint": {"en": "reproducibility: how many retests still failed", "al": "reproducibility: sa rifirmime dështuan prap"},
    "reproducibility_label": {"en": "reproduced", "al": "riprodhuar"},
    "col_categories": {"en": "Categories", "al": "Kategoritë"},
    "col_mode": {"en": "Mode", "al": "Modaliteti"},
    "no_configs_yet": {"en": "No scan configurations yet.", "al": "S'ka konfigurime skanimi ende."},

    # ---- tasks.html ----
    "run_scan_title": {"en": "Run a Scan", "al": "Nis një Skanim"},
    "run_scan_sub": {"en": "Select a target and configuration, then start it", "al": "Zgjidh objektivin dhe konfigurimin, pastaj nise"},
    "field_target": {"en": "Target", "al": "Objektivi"},
    "field_scan_config": {"en": "Scan Configuration", "al": "Konfigurimi i Skanimit"},
    "btn_start_scan": {"en": "Start Scan", "al": "Nis Skanimin"},
    "recent_tasks": {"en": "Recent tasks", "al": "Detyrat e fundit"},
    "btn_prev_page": {"en": "Prev", "al": "Mbrapa"},
    "btn_next_page": {"en": "Next", "al": "Para"},
    "col_config": {"en": "Config", "al": "Konfigurimi"},
    "no_tasks_yet": {"en": "No tasks yet.", "al": "S'ka detyra ende."},
    "tab_all_scans": {"en": "All scans", "al": "Të gjitha skanimet"},
    "tab_critical_findings": {"en": "Critical findings", "al": "Gjetjet kritike"},
    "critical_findings_title": {"en": "Critical findings", "al": "Gjetjet kritike"},
    "critical_findings_sub": {"en": "Confirmed vulnerabilities from every scan, worst first. Click a finding to read it.",
                              "al": "Dobësi të konfirmuara nga çdo skanim, më të rëndat të parat. Kliko një gjetje për ta lexuar."},
    "sev_high_critical": {"en": "High + Critical", "al": "Të larta + Kritike"},
    "sev_critical": {"en": "Critical", "al": "Kritike"},
    "sev_high": {"en": "High", "al": "Të larta"},
    "sev_medium": {"en": "Medium", "al": "Mesatare"},
    "sev_low": {"en": "Low", "al": "Të ulëta"},
    "sev_all": {"en": "All severities", "al": "Të gjitha"},
    "col_finding": {"en": "Finding", "al": "Gjetja"},
    "col_scan": {"en": "Scan", "al": "Skanimi"},
    "no_critical_findings": {"en": "No confirmed vulnerabilities at this severity.",
                             "al": "Nuk ka dobësi të konfirmuara me këtë ashpërsi."},
    "chart_no_findings": {"en": "No vulnerabilities confirmed yet", "al": "Ende pa dobësi të konfirmuara"},
    "chart_legend_resisted": {"en": "Resisted", "al": "Rezistoi"},
    "chart_legend_vulnerable": {"en": "Vulnerable", "al": "I cenueshëm"},
    "chart_legend_review": {"en": "Needs review", "al": "Për rishikim"},
    "chart_legend_error": {"en": "Not evaluated", "al": "Pa vlerësuar"},
    "chart_out_of_scope": {"en": "out of scope", "al": "jashtë fushëveprimit"},
    "chart_tested": {"en": "tested", "al": "testuar"},
    "chart_not_tested": {"en": "not tested yet", "al": "ende pa testuar"},
    "view_all": {"en": "View all", "al": "Shiko të gjitha"},
    "btn_view_results": {"en": "View results", "al": "Shiko rezultatet"},
    "open_scan_hint": {"en": "Open this scan", "al": "Hap këtë skanim"},
    "btn_watch_live": {"en": "Watch live", "al": "Shiko live"},
    "btn_force_stop": {"en": "Force stop", "al": "Ndalo me force"},
    "confirm_force_stop": {"en": "Force-stop this task? Use this only if it is stuck showing \"running\" with the normal Stop having no effect.",
                            "al": "Ta ndalosh me force kete task? Perdore vetem nese ka mbetur \"running\" dhe Stop normal nuk ka efekt."},
    "col_action": {"en": "Action", "al": "Veprim"},

    # ---- results.html ----
    "results_title": {"en": "Scan Results", "al": "Rezultatet e Skanimit"},
    "results_sub": {"en": "View and analyze your scan findings", "al": "Shiko dhe analizo gjetjet e skanimeve"},
    "btn_view": {"en": "View", "al": "Shiko"},
    "no_results_yet": {"en": "No results yet.", "al": "S'ka rezultate ende."},
    "btn_compare_scans": {"en": "Compare scans", "al": "Krahaso skanime"},
    "results_selected_one": {"en": "1 selected", "al": "1 i zgjedhur"},
    "results_selected_many": {"en": "selected", "al": "të zgjedhur"},
    "btn_delete": {"en": "Delete", "al": "Fshi"},
    "confirm_delete_results": {"en": "Delete the selected scan result(s)? This cannot be undone.",
                                "al": "Te fshihen rezultatet e zgjedhura? Ky veprim nuk mund te kthehet mbrapsht."},

    # ---- result_detail.html ----
    "scan_hash": {"en": "Scan", "al": "Skanimi"},
    "target_label": {"en": "Target:", "al": "Objektivi:"},
    "risk_score_label": {"en": "Risk score:", "al": "Risku:"},
    "btn_export_pdf": {"en": "Export PDF", "al": "Eksporto PDF"},
    "btn_export_json": {"en": "Export JSON", "al": "Eksporto JSON"},
    "btn_export_csv": {"en": "Export CSV", "al": "Eksporto CSV"},
    "col_id": {"en": "ID", "al": "ID"},
    "col_owasp": {"en": "OWASP", "al": "OWASP"},
    "col_severity": {"en": "Severity", "al": "Ashpërsia"},
    "col_verdict": {"en": "Verdict", "al": "Verdikti"},
    "col_triage": {"en": "Triage", "al": "Triazhi"},
    "btn_details": {"en": "Details", "al": "Detaje"},

    # ---- finding_detail.html ----
    "severity_label": {"en": "Severity:", "al": "Ashpërsia:"},
    "verdict_label": {"en": "Verdict:", "al": "Verdikti:"},
    "confidence_label": {"en": "confidence", "al": "besueshmëri"},
    "description_title": {"en": "Description", "al": "Përshkrimi"},
    "prompt_sent_title": {"en": "Prompt sent", "al": "Prompti i dërguar"},
    "raw_response_title": {"en": "Raw response", "al": "Përgjigja e papërpunuar"},
    "triage_title": {"en": "Triage", "al": "Triazhi"},
    "current_status_label": {"en": "Current status:", "al": "Statusi aktual:"},
    "triaged_by_label": {"en": "triaged by", "al": "triazhuar nga"},
    "field_triage_status": {"en": "Status", "al": "Statusi"},
    "field_triage_note": {"en": "Note", "al": "Shënim"},
    "triage_note_placeholder": {"en": "Why was this marked this way?", "al": "Pse u shenua keshtu?"},
    "btn_save_triage": {"en": "Save", "al": "Ruaj"},
    "triage_open": {"en": "Open", "al": "Hapur"},
    "triage_false_positive": {"en": "False Positive", "al": "False Positive"},
    "triage_accepted_risk": {"en": "Accepted Risk", "al": "Risk i Pranuar"},

    # ---- results_compare.html ----
    "compare_title": {"en": "Compare Scans", "al": "Krahaso Skanime"},
    "compare_sub": {"en": "See which findings were fixed, which are new, between two scans of the same target",
                     "al": "Shiko cilat gjetje u rregulluan, cilat jane te reja, mes dy skanimeve te te njejtit objektiv"},
    "compare_from_label": {"en": "From (older scan)", "al": "Nga (skanimi me i vjeter)"},
    "compare_to_label": {"en": "To (newer scan)", "al": "Deri (skanimi me i ri)"},
    "btn_compare": {"en": "Compare", "al": "Krahaso"},
    "compare_fixed_title": {"en": "Fixed since last scan", "al": "Te rregulluara que nga skanimi i vjeter"},
    "compare_new_title": {"en": "New findings", "al": "Gjetje te reja"},
    "compare_unchanged_title": {"en": "Still present", "al": "Ende prezente"},
    "compare_none": {"en": "None.", "al": "Asnje."},

    # ---- rules.html ----
    "rules_title": {"en": "Rules / Payload Library", "al": "Rregullat / Libraria e Payload-ve"},
    "rules_sub_suffix": {"en": "payloads total, community sources plus CYBERGUARD LLM original research",
                          "al": "payload gjithsej, burime komuniteti plus kërkim origjinal CYBERGUARD LLM"},
    "col_source": {"en": "Source", "al": "Burimi"},
    "col_prompt": {"en": "Prompt", "al": "Prompti"},
    "btn_add_custom_rule": {"en": "Add Custom Rule", "al": "Shto Rregull Personalizuar"},
    "custom_rule_badge": {"en": "Custom (UI)", "al": "Personalizuar (UI)"},
    "confirm_delete_rule": {"en": "Delete this custom rule?", "al": "Fshi kete rregull personalizuar?"},
    "rules_bulk_hint": {"en": "Any payload can be selected and deleted, including the built-in library - that removes it permanently from its source file.",
                         "al": "Çdo payload mund te zgjidhet dhe fshihet, perfshire ato te integruarit - kjo e heq perfundimisht nga skedari burim."},

    # ---- rule_new.html ----
    "rule_new_title": {"en": "Add Custom Rule", "al": "Shto Rregull Personalizuar"},
    "rule_new_sub": {"en": "Add your own payload for a specific engagement, without touching the built-in library files",
                      "al": "Shto payload-in tend per nje engagement specifik, pa prekur file-t e librarise se integruar"},
    "field_rule_id": {"en": "Rule ID", "al": "Rule ID"},
    "field_owasp": {"en": "OWASP Category", "al": "Kategoria OWASP"},
    "field_severity": {"en": "Severity", "al": "Ashpersia"},
    "field_module": {"en": "Module / Engagement name (optional)", "al": "Moduli / Emri Engagement (opsional)"},
    "field_technique": {"en": "Technique tag (optional)", "al": "Tag Teknike (opsional)"},
    "field_rule_prompt": {"en": "Prompt (or turns, one per line)", "al": "Prompti (ose turnet, nje per rresht)"},
    "rule_prompt_placeholder": {"en": "Enter one prompt for a single-turn test, or several lines for a multi-turn sequence",
                                  "al": "Vendos nje prompt per test single-turn, ose disa rreshta per sekuence multi-turn"},
    "rule_prompt_hint": {"en": "One line = single-turn test. Multiple lines = multi-turn sequence, sent in order on the same conversation.",
                          "al": "Nje rresht = test single-turn. Disa rreshta = sekuence multi-turn, dergohen me rradhe ne te njejten bisede."},
    "field_fail_conditions": {"en": "Fail conditions (regex, one per line)", "al": "Fail conditions (regex, nje per rresht)"},
    "field_pass_conditions": {"en": "Pass conditions (regex, one per line, optional)", "al": "Pass conditions (regex, nje per rresht, opsional)"},
    "rule_conditions_hint": {"en": "At least one regex required. Matched against the target's response text.",
                              "al": "Te paktën nje regex kerkohet. Krahasohet kundrejt tekstit te pergjigjes se objektivit."},
    "btn_save_rule": {"en": "Save rule", "al": "Ruaj rregullin"},

    # ---- activity.html ----
    "activity_title": {"en": "Activity Log", "al": "Regjistri i Aktivitetit"},
    "activity_sub": {"en": "Track all user actions and system events", "al": "Ndiq të gjitha veprimet e përdoruesve dhe ngjarjet e sistemit"},
    "col_time": {"en": "Time", "al": "Koha"},
    "col_user": {"en": "User", "al": "Përdoruesi"},
    "col_action": {"en": "Action", "al": "Veprimi"},
    "col_details": {"en": "Details", "al": "Detaje"},
    "tab_activity": {"en": "Activity", "al": "Aktiviteti"},
    "tab_errors": {"en": "Errors", "al": "Gabimet"},
    "col_source": {"en": "Source", "al": "Burimi"},
    "col_what": {"en": "What happened", "al": "Çfarë ndodhi"},
    "no_errors_yet": {"en": "No errors recorded.", "al": "Asnjë gabim i regjistruar."},
    "errors_sub": {"en": "Why scans stopped early or skipped a check: timeouts, unreachable targets, crashed modules, restarts.",
                   "al": "Pse skanimet u ndalën herët ose anashkaluan një kontroll: timeout, objektiva të paarritshëm, module të rrëzuara, rinisje."},
    "no_activity_yet": {"en": "No activity yet.", "al": "S'ka aktivitet ende."},

    # ---- settings.html ----
    "settings_title": {"en": "Settings", "al": "Cilësimet"},
    "settings_sub": {"en": "Manage your account, system preferences and integrations",
                      "al": "Menaxho llogarinë, preferencat e sistemit dhe integrimet"},
    "tab_account": {"en": "Account", "al": "Llogaria"},
    "tab_user_management": {"en": "User Management", "al": "Menaxhimi i Përdoruesve"},
    "tab_scan_settings": {"en": "Scan Settings", "al": "Cilësimet e Skanimit"},
    "ai_config_status_configured": {"en": "API configured", "al": "API e konfiguruar"},
    "ai_config_status_not_configured": {"en": "No API key configured yet", "al": "Ska API key te konfiguruar ende"},
    "btn_copy_config": {"en": "Copy config", "al": "Kopjo konfigurimin"},
    "model_pick_cheap": {"en": "cheapest", "al": "me e lira"},
    "model_pick_balanced": {"en": "balanced", "al": "e balancuar"},
    "model_pick_strongest": {"en": "strongest", "al": "me e forta"},
    "click_to_edit_hint": {"en": "click to edit", "al": "kliko për me ndryshu"},
    "proxy_status_on": {"en": "Proxy enabled", "al": "Proxy aktiv"},
    "proxy_status_off": {"en": "Proxy disabled", "al": "Proxy joaktiv"},
    "stealth_status_on": {"en": "Stealth mode enabled", "al": "Stealth mode aktiv"},
    "stealth_status_off": {"en": "Stealth mode disabled", "al": "Stealth mode joaktiv"},
    "canary_status_on": {"en": "Canary configured", "al": "Canary i konfiguruar"},
    "canary_status_off": {"en": "No canary configured", "al": "Ska canary te konfiguruar"},
    "default_creds_warning_title": {"en": "Default credentials detected!", "al": "U zbuluan kredenciale default!"},
    "default_creds_warning_text": {"en": "Change your password below.", "al": "Ndrysho fjalëkalimin më poshtë."},
    "change_password_title": {"en": "Change password", "al": "Ndrysho fjalëkalimin"},
    "field_new_password": {"en": "New password", "al": "Fjalëkalimi i ri"},
    "btn_save": {"en": "Save", "al": "Ruaj"},
    "your_account_title": {"en": "Your account", "al": "Llogaria jote"},
    "field_username": {"en": "Username", "al": "Përdoruesi"},
    "field_role": {"en": "Role", "al": "Roli"},
    "role_explanation": {
        "en": "Operator: can view everything and run scans. Administrator: can also manage targets and scan configs. Global Administrator: can also make vital system changes (users, AI mode, proxy).",
        "al": "Operator: sheh gjithçka dhe nis skanime. Administrator: menaxhon edhe objektivat dhe konfigurimet. Global Administrator: bën edhe ndryshime vitale të sistemit (users, AI mode, proxy).",
    },
    "user_management_title": {"en": "User management", "al": "Menaxhimi i Përdoruesve"},
    "field_password": {"en": "Password", "al": "Fjalëkalimi"},
    "btn_create_user": {"en": "Create user", "al": "Krijo Përdorues"},
    "you_label": {"en": "you", "al": "ti"},
    "scan_engine_mode_title": {"en": "Scan engine mode", "al": "Modaliteti i Motorit të Skanimit"},
    "scan_mode_explanation": {
        "en": "Offline mode replays the static OWASP LLM Top 10 payload library. AI-Powered mode plugs in an AI agent via API key that dynamically generates and escalates adversarial prompts against the target in real time, essentially one AI agent attacking another AI agent, and judges each response, then produces findings. Works with any OpenAI-compatible chat completions endpoint (OpenAI, Azure OpenAI-compatible, OpenRouter, local vLLM/Ollama servers, etc.), so it is not tied to a single provider. Note: once an API key is set below, Offline mode also starts using this AI model as its evaluator for every static payload's response (catching paraphrased or partial compliance that plain regex matching misses), instead of regex pattern matching alone. Leave the key blank to keep Offline mode purely regex-based.",
        "al": "Modaliteti Offline përsërit librarinë statike të payload-ve OWASP LLM Top 10. Modaliteti AI-Powered lidh një AI agent përmes API key që gjeneron dhe forcon prompte sulmuese kundrejt objektivit në kohë reale, në thelb një AI agent sulmon një AI agent tjetër, dhe gjykon çdo përgjigje, pastaj prodhon gjetje. Punon me çdo endpoint OpenAI-compatible (OpenAI, Azure OpenAI-compatible, OpenRouter, servera lokalë vLLM/Ollama etj.), pra s'është i lidhur me vetëm një provider. Shënim: sapo vendoset një API key më poshtë, edhe modaliteti Offline fillon ta përdorë këtë model AI si evaluator për çdo përgjigje të payload-ve statikë (duke kapur compliance të parafrazuar ose të pjesshme që regex e humbet), në vend të vetëm regex pattern matching. Lëre fushën e API key bosh nëse do që Offline të mbetet thjesht regex-based.",
    },
    "field_scan_mode": {"en": "Scan mode", "al": "Modaliteti i skanimit"},
    "offline_option": {"en": "Offline (static payload library)", "al": "Offline (libraria statike e payload-ve)"},
    "ai_powered_option": {"en": "AI-Powered (adversarial AI agent)", "al": "AI-Powered (AI agent sulmues)"},
    "field_ai_provider": {"en": "AI Provider", "al": "Ofruesi AI"},
    "provider_openai_compatible": {"en": "OpenAI-compatible (OpenAI, DeepSeek, Groq, Mistral, local, OpenRouter, ...)",
                                    "al": "OpenAI-compatible (OpenAI, DeepSeek, Groq, Mistral, lokal, OpenRouter, ...)"},
    "provider_anthropic": {"en": "Anthropic (Claude)", "al": "Anthropic (Claude)"},
    "provider_gemini": {"en": "Google (Gemini)", "al": "Google (Gemini)"},
    "provider_explanation": {
        "en": "Pick your provider, paste its API key below, that's it - the base URL and model are pre-filled "
              "for you and this app speaks each provider's native format internally, so DeepSeek/Groq/etc just "
              "work under \"OpenAI-compatible\" with their own base URL, while Anthropic and Google use their own "
              "native API automatically.",
        "al": "Zgjidh ofruesin, ngjit API key-n poshtë, kaq - base URL dhe modeli plotësohen vetë dhe aplikacioni "
              "flet formatin native të secilit ofrues brenda, kështu që DeepSeek/Groq/etj punojnë thjesht nën "
              "\"OpenAI-compatible\" me base URL-në e tyre, ndërsa Anthropic dhe Google përdorin API-n e tyre "
              "native automatikisht."},
    "ai_api_key_hint": {
        "en": "Just the API key from your provider's dashboard - no other setup needed.",
        "al": "Thjesht API key nga dashboard-i i ofruesit tënd - s'duhet asgjë tjetër."},
    "field_ai_api_base": {"en": "AI API base URL", "al": "AI API base URL"},
    "field_model": {"en": "Model", "al": "Modeli"},
    "field_ai_api_key": {"en": "AI API key", "al": "AI API key"},
    "ai_api_key_placeholder_stored": {"en": "stored (leave blank to keep)", "al": "e ruajtur (lëre bosh për ta mbajtur)"},
    "ai_key_saved_label": {"en": "Saved", "al": "E ruajtur"},
    "btn_change_key": {"en": "Change key", "al": "Ndrysho key"},
    "btn_cancel_change": {"en": "Cancel", "al": "Anulo"},
    "btn_remove_key": {"en": "Remove key", "al": "Hiq key"},
    "confirm_remove_key": {"en": "Remove the stored AI API key?", "al": "Ta heq AI API key të ruajtur?"},
    "btn_save_scan_mode": {"en": "Save scan mode", "al": "Ruaj Modalitetin"},
    "proxy_routing_title": {"en": "Proxy routing (VPN/Proxy)", "al": "Ruting përmes Proxy (VPN/Proxy)"},
    "proxy_explanation": {
        "en": "A true OS-level VPN would need to control routing for the whole machine with root access, which does not fit cleanly inside a web app. What does fit cleanly is application-layer proxy routing: every outbound request this tool makes to a target (discovery pings and scan payloads alike) can be routed through an HTTP or SOCKS5 proxy, so the target sees the proxy's IP address instead of this server's IP. Set an HTTP proxy as http://host:port or http://user:pass@host:port, or a SOCKS5 proxy as socks5://host:port. Use \"Test Proxy\" to confirm it works; it fetches your outbound IP through the proxy so you can verify it actually changed.",
        "al": "Një VPN i vërtetë në nivel OS do të kërkonte kontroll të rutingut për gjithë makinën me akses root, gjë që s'përshtatet mirë brenda një web app. Ajo që përshtatet mirë është rutingu në nivel aplikacioni përmes proxy: çdo kërkesë dalëse që ky mjet i bën një objektivi (si ping-et e zbulimit ashtu edhe payload-et e skanimit) mund të kalojë përmes një proxy HTTP ose SOCKS5, kështu që objektivi sheh IP-në e proxy-t në vend të IP-së së këtij serveri. Vendos një proxy HTTP si http://host:port ose http://user:pass@host:port, ose një proxy SOCKS5 si socks5://host:port. Përdor \"Test Proxy\" për të konfirmuar që punon; ai merr IP-në tënde dalëse përmes proxy-t që ta verifikosh që vërtet ka ndryshuar.",
    },
    "enable_proxy_checkbox": {"en": "Enable proxy routing for all scan traffic", "al": "Aktivizo ruting proxy për gjithë trafikun e skanimit"},
    "field_proxy_url": {"en": "Proxy URL", "al": "Proxy URL"},
    "btn_save_proxy": {"en": "Save proxy settings", "al": "Ruaj Cilësimet e Proxy"},
    "btn_test_proxy": {"en": "Test Proxy", "al": "Testo Proxy"},
    "stealth_mode_title": {"en": "Stealth / throttling mode", "al": "Modaliteti Stealth / Throttling"},
    "stealth_explanation": {
        "en": "When testing a real, authorized production target, firing adversarial payloads back-to-back with the default python-requests signature is the easiest way to get the scan itself blocked by basic bot detection or rate limiting, which has nothing to do with the LLM's actual security. Stealth mode adds a randomized delay between requests and rotates a realistic browser User-Agent header, so an authorized assessment does not trip the target's unrelated anti-bot defenses. This does not help bypass any security control you are not authorized to test.",
        "al": "Kur testohet një objektiv real production i autorizuar, dergimi i payload-ve njeri pas tjetrit me signature-in default te python-requests eshte menyra me e lehte qe vete skanimi te bllokohet nga bot detection apo rate limiting bazike, gje qe s'ka lidhje me sigurine reale te LLM-se. Stealth mode shton nje delay te randomizuar mes kerkesave dhe rotullon nje User-Agent realist browser-i, qe nje vleresim i autorizuar te mos trigger-oje mbrojtjet anti-bot te paqena te objektivit. Kjo s'ndihmon per te anashkaluar ndonje kontroll sigurie qe s'je i autorizuar ta testosh.",
    },
    "enable_stealth_checkbox": {"en": "Enable randomized delay + User-Agent rotation", "al": "Aktivizo delay te randomizuar + rotullim User-Agent"},
    "rotate_ua_checkbox": {"en": "Rotate User-Agent header", "al": "Rotullo header-in User-Agent"},
    "field_delay_min": {"en": "Min delay (ms)", "al": "Delay minimal (ms)"},
    "field_delay_max": {"en": "Max delay (ms)", "al": "Delay maksimal (ms)"},
    "btn_save_stealth": {"en": "Save stealth settings", "al": "Ruaj Cilesimet Stealth"},
    "role_operator": {"en": "Operator", "al": "Operator"},
    "role_administrator": {"en": "Administrator", "al": "Administrator"},
    "role_global_administrator": {"en": "Global Administrator", "al": "Global Administrator"},
    "confirm_delete_user": {"en": "Delete this user?", "al": "Fshi këtë përdorues?"},
    "confirm_delete_target": {"en": "Delete this target? This cannot be undone.",
                               "al": "Fshi kete target? Ky veprim nuk mund te kthehet mbrapsht."},
    "confirm_delete_targets": {"en": "Delete the selected target(s)? This cannot be undone.",
                                "al": "Te fshihen target-et e zgjedhur? Ky veprim nuk mund te kthehet mbrapsht."},
    "confirm_delete_configs": {"en": "Delete the selected scan config(s)? This cannot be undone.",
                                "al": "Te fshihen konfigurimet e zgjedhura? Ky veprim nuk mund te kthehet mbrapsht."},
    "confirm_delete_rules": {"en": "Delete the selected payload(s)? Built-in payloads are removed from their source file permanently, not just hidden.",
                              "al": "Te fshihen payload-et e zgjedhur? Ato te integruarit hiqen perfundimisht nga skedari burim, jo vetem fshihen nga lista."},
    "flash_target_created": {"en": "Target saved.", "al": "Target-i u ruajt."},
    "flash_target_context_updated": {"en": "Business context updated.", "al": "Konteksti u perditesua."},
    "flash_target_updated": {"en": "Target updated.", "al": "Target-i u perditesua."},
    "flash_target_deleted": {"en": "Target deleted.", "al": "Target-i u fshi."},
    "flash_config_created": {"en": "Scan configuration saved.", "al": "Konfigurimi i skanimit u ruajt."},
    "flash_finding_triaged": {"en": "Finding updated.", "al": "Gjetja u perditesua."},
    "flash_rule_created": {"en": "Custom rule saved.", "al": "Rregulli personalizuar u ruajt."},
    "flash_rule_deleted": {"en": "Custom rule deleted.", "al": "Rregulli personalizuar u fshi."},
    "flash_password_changed": {"en": "Password changed.", "al": "Fjalekalimi u ndryshua."},
    "flash_user_created": {"en": "User created.", "al": "Perdoruesi u krijua."},
    "flash_user_role_changed": {"en": "User role updated.", "al": "Roli i perdoruesit u perditesua."},
    "flash_user_deleted": {"en": "User deleted.", "al": "Perdoruesi u fshi."},
    "flash_scan_mode_updated": {"en": "Scan mode updated.", "al": "Modaliteti i skanimit u perditesua."},
    "flash_ai_key_removed": {"en": "AI API key removed.", "al": "AI API key u hoq."},
    "flash_proxy_updated": {"en": "Proxy settings updated.", "al": "Rregullimet e proxy u perditesuan."},
    "flash_stealth_updated": {"en": "Stealth settings updated.", "al": "Rregullimet e stealth u perditesuan."},
    "flash_canary_updated": {"en": "Canary settings updated.", "al": "Rregullimet e canary u perditesuan."},
    "section_ai_powered": {"en": "AI-Powered Mode", "al": "Modaliteti AI-Powered"},
    "section_external_tools": {"en": "External Tools (Garak / PyRIT)", "al": "Mjete te Jashtme (Garak / PyRIT)"},
    "section_reliability": {"en": "Reliability (retest, mutations)", "al": "Besueshmeria (retest, mutations)"},
    "no_matching_results": {"en": "No matching scans.", "al": "Nuk u gjetën skanime."},
    "judge_confidence": {"en": "Judge confidence", "al": "Besimi i gjykuesit AI"},
    "help_id": {"en": "Identifier of the rule or attempt that produced this record.", "al": "Identifikuesi i rregullit ose tentativës që krijoi këtë rezultat."},
    "help_owasp": {"en": "The OWASP risk category tested by this attempt.", "al": "Kategoria e rrezikut OWASP e testuar nga kjo tentativë."},
    "help_severity": {"en": "Assigned impact/risk level for this test or finding. The verdict says whether the attempt demonstrated the weakness. High + PASS means that this attempt did not demonstrate the high-risk scenario.", "al": "Niveli i ndikimit/rrezikut të këtij testi ose gjetjeje. Verdikti tregon nëse tentativa e demonstroi dobësinë. High + PASS do të thotë se kjo tentativë nuk e demonstroi skenarin me rrezik të lartë."},
    "help_verdict": {"en": "PASS: weakness not demonstrated. FAIL: evaluation indicates success; inspect the evidence. REVIEW: unresolved. ERROR: could not evaluate. INFO: informational record. PASS does not establish overall safety.", "al": "PASS: dobësia nuk u demonstrua. FAIL: vlerësimi tregon sukses; kontrollo provat. REVIEW: i pazgjidhur. ERROR: nuk mund të vlerësohej. INFO: informacion. PASS nuk vërteton sigurinë e përgjithshme."},
    "help_confidence": {"en": "The AI judge's self-reported confidence in its verdict, not the probability that the target is vulnerable. It is not a guarantee of correctness. A dash means no judge confidence was recorded.", "al": "Besimi i vetëraportuar i gjykuesit AI në verdiktin e tij, jo probabiliteti që targeti është i cenueshëm. Nuk është garanci saktësie. Viza tregon se nuk u regjistrua besim i gjykuesit."},
    "help_triage": {"en": "Analyst disposition: Open, False Positive or Accepted Risk. Triage does not change the recorded verdict or risk score.", "al": "Statusi sipas analistit: E hapur, Pozitiv i rremë ose Rrezik i pranuar. Triage nuk ndryshon verdiktin e regjistruar ose pikët e rrezikut."},
    "filter_all": {"en": "All", "al": "Të gjitha"},
    "filter_engine": {"en": "Engine", "al": "Motori"},
    "filter_category": {"en": "Category", "al": "Kategoria"},
    "filter_apply": {"en": "Apply filters", "al": "Apliko filtrat"},
    "filter_reset": {"en": "Reset filters", "al": "Hiq filtrat"},
    "finding_previous": {"en": "Previous finding", "al": "Gjetja e mëparshme"},
    "finding_next": {"en": "Next finding", "al": "Gjetja pasuese"},
    "finding_no_match": {"en": "This finding no longer matches the selected filters. Return to the list to review the current results.", "al": "Kjo gjetje nuk përputhet më me filtrat e zgjedhur. Kthehu te lista për rezultatet aktuale."},
    "finding_empty": {"en": "No findings match these filters.", "al": "Asnjë gjetje nuk përputhet me këta filtra."},
    "copy_prompt": {"en": "Copy prompt", "al": "Kopjo promptin"},
    "copy_response": {"en": "Copy response", "al": "Kopjo përgjigjen"},
    "copy_done": {"en": "Copied", "al": "U kopjua"},
    "copy_failed": {"en": "Copy failed. Select the text and copy it manually.", "al": "Kopjimi dështoi. Zgjidh tekstin dhe kopjoje manualisht."},
    "btn_search": {"en": "Search", "al": "Kërko"},
    "btn_clear_search": {"en": "Clear", "al": "Pastro"},
    "pagination_label": {"en": "Pages", "al": "Faqet"},
    "search_placeholder": {"en": "Search...", "al": "Kerko..."},
    "section_extra_modules": {"en": "Additional Modules (canary, recon, fingerprint, session isolation)",
                               "al": "Module Shtese (canary, recon, fingerprint, session isolation)"},
}


def translate(key, lang="en"):
    entry = TRANSLATIONS.get(key)
    if not entry:
        return key
    return entry.get(lang) or entry.get("en") or key
