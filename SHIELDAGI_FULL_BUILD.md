# ShieldAGI 2.0 — Autonomous Full Build

## TU MISIÓN

Eres el constructor principal de ShieldAGI 2.0. Tu trabajo es completar TODA la plataforma desde Phase C hasta Phase E sin intervención humana. Lee CLAUDE_CODE_PROMPT.md para el contexto completo del proyecto. Phase A (Foundation) y Phase B (Attack Engine) ya están completas — los 14 tools de Rust están implementados.

REGLAS ABSOLUTAS:
- NO hagas stubs, NO dejes TODOs, NO dejes placeholders. Todo debe ser código funcional.
- Después de cada Phase, haz commit con un mensaje descriptivo.
- Si algo falla, arréglalo tú mismo — no preguntes al usuario.
- Si necesitas instalar dependencias, instálalas.
- Lee los archivos existentes ANTES de modificarlos para entender el contexto.
- Cada archivo nuevo debe tener comentarios explicando qué hace.
- Al terminar todo, haz un commit final con "ShieldAGI 2.0 — Production Ready"

---

## PHASE C: REMEDIATION ENGINE

### C1. Vulnerability Report Types (`tools/src/report_types.rs`)
Crea los structs de Rust que representan el reporte de vulnerabilidades:
- `VulnerabilityReport` — struct principal con: report_id, target info (domain, repo, framework), scan_timestamp, summary (totals por severidad, risk_score 0-100, top 3 priorities), vector de Vulnerability, vector de AttackChain
- `Vulnerability` — id (SHIELD-XXXX), category (sqli/xss/csrf/auth/ssrf/traversal/idor/misconfig/dependency/secret), severity (CRITICAL/HIGH/MEDIUM/LOW), cvss_score f32, cvss_vector String, title, description, affected_files Vec<AffectedFile>, endpoint, method, parameter, exploitable bool, proof_of_concept String, remediation RemediationGuidance
- `AffectedFile` — path String, lines Vec<u32>
- `RemediationGuidance` — playbook String, chain_wall String, complexity (TRIVIAL/SIMPLE/MODERATE/COMPLEX), fix_description, dependencies Vec<String>
- `AttackChain` — name, vulnerability_ids Vec<String>, combined_impact, combined_severity
- Implementa Serialize, Deserialize, Default para todos
- Implementa métodos helper: `sort_by_severity()`, `get_critical()`, `get_by_category()`

### C2. Framework Detector (`tools/src/framework_detect.rs`)
Detecta automáticamente qué frameworks usa el repo target:
- `detect_frameworks(repo_path: &str) -> Vec<FrameworkInfo>`
- `FrameworkInfo` struct: framework_type (NextJS/Express/Supabase/Django/RustWeb/Unknown), version String, config_paths Vec<String>, entry_points Vec<String>, package_manager String
- Detección: leer package.json, requirements.txt, Cargo.toml, vercel.json, supabase/config.toml, manage.py, next.config.*, docker-compose.yml
- Para cada framework detectado, identificar los archivos de entrada principales (middleware.ts, app.js, settings.py, etc.)
- Implementar como tool de OpenFang con schema JSON para que los agentes lo llamen

### C3. Remediation Pipeline (`tools/src/remediation_pipeline.rs`)
El orquestador principal — esto es el cerebro de Phase 2:

```
pub struct RemediationPipeline {
    report: VulnerabilityReport,
    frameworks: Vec<FrameworkInfo>,
    workspace_path: String,
    state: PipelineState,
    results: Vec<RemediationResult>,
}

pub enum PipelineState {
    Loading, Planning, Executing, Verifying, CreatingPR, Complete, Failed(String)
}

pub struct RemediationResult {
    vulnerability_id: String,
    status: FixStatus,  // Fixed, Skipped, Failed, NeedsManualReview
    files_modified: Vec<String>,
    commit_hash: Option<String>,
    verification_passed: bool,
    notes: String,
}
```

Implementa estos métodos:
- `new(report_path, repo_path)` — carga reporte, clona repo, detecta framework
- `plan()` — ordena vulns por severidad (CRITICAL primero), resuelve dependencias entre fixes (ej: arreglar auth antes que IDOR), agrupa por archivo afectado
- `execute()` — para cada vulnerabilidad en orden:
  1. Lee el archivo afectado
  2. Determina qué playbook aplicar según la categoría
  3. Lee el playbook de `playbooks/{category}_remediation.md`
  4. Aplica el fix según el framework detectado
  5. Si el fix necesita nuevas dependencias, agrégalas a package.json/requirements.txt
  6. Ejecuta los tests del proyecto
  7. Si los tests pasan: commit con mensaje `fix(security): {descripción} — {SHIELD-ID}`
  8. Si los tests fallan: intenta ajustar el fix, si no se puede, marca como NeedsManualReview
- `verify()` — para cada vuln arreglada, re-ejecuta la herramienta de ataque correspondiente (ej: sqlmap para SQLi, xss_inject para XSS) y confirma que ya no es explotable
- `generate_pr()` — crea el PR con toda la información

### C4. Chain Walls Injector (`tools/src/chain_walls_injector.rs`)
Inyecta automáticamente Chain Walls según el framework:
- `inject_chain_walls(repo_path, frameworks) -> Result<Vec<String>, String>` (retorna archivos modificados)
- Para Next.js: lee chain-walls/nextjs/middleware.ts, adáptalo al proyecto (ajustar ALLOWED_ORIGINS, PUBLIC_PATHS según las rutas encontradas), crear/actualizar middleware.ts en la raíz del proyecto
- Para Express: lee chain-walls/express/chain-walls.middleware.js, encuentra el archivo principal de la app (app.js, server.js, index.js), inserta `app.use(chainWalls())` ANTES de las rutas, agrega `helmet` a package.json si no existe
- Para Supabase: lee chain-walls/supabase/chain-walls.ts, crea supabase/functions/_shared/chain-walls.ts, encuentra TODOS los edge functions y envuélvelos con `withChainWalls()`
- Para Django: lee chain-walls/django/chain_walls.py, crea el archivo en el proyecto, agrega a MIDDLEWARE en settings.py como PRIMER middleware
- IMPORTANTE: si ya existe un middleware, NO lo sobrescribas — merge las funcionalidades

### C5. PR Generator (`tools/src/pr_generator.rs`)
Genera el Pull Request con descripción completa:
- `generate_pr(pipeline_results, report) -> PullRequestContent`
- `PullRequestContent`: title, body (markdown), branch_name, labels
- El body debe incluir:
  - Tabla resumen: | Vulnerability | Severity | Status | File |
  - Para cada fix: descripción, antes/después del código (diff format), tests pasados
  - Sección de Chain Walls: qué se implementó y por qué
  - Sección de acciones manuales: lo que necesita review humano
  - Métricas: total vulns encontradas, total arregladas, % de cobertura
- Ejecuta los comandos git: branch, add, commit, push vía shell

### C6. Verify Fix (`tools/src/verify_fix.rs`)
Re-ejecuta herramientas de ataque para confirmar fixes:
- `verify_vulnerability_fix(vuln: &Vulnerability, target_url: &str) -> VerificationResult`
- Mapeo de categoría a herramienta de verificación:
  - sqli → sqlmap_attack
  - xss → xss_inject
  - csrf → csrf_test
  - auth → brute_force
  - ssrf → ssrf_probe
  - traversal → path_traverse
  - idor → idor_test
  - misconfig → header_audit
  - dependency → dep_audit
  - secret → secret_scan
- `VerificationResult`: vulnerability_id, tool_used, still_exploitable bool, details String

### C7. Wire everything together
- Actualiza `tools/src/lib.rs`:
  - Agrega los módulos: `pub mod report_types; pub mod framework_detect; pub mod remediation_pipeline; pub mod chain_walls_injector; pub mod pr_generator; pub mod verify_fix;`
  - Registra nuevos tools: `detect_framework`, `run_remediation`, `inject_chain_walls`, `create_pr`, `verify_fix`
  - Agrega al execute_shieldagi_tool() dispatch
- Actualiza `tools/Cargo.toml` con dependencias necesarias
- Actualiza `agents/shield-remediator/agent.toml` con los nuevos tools en el allowlist

### C8. COMMIT
```
git add -A
git commit -m "Phase C: Remediation Engine — pipeline, chain walls injector, PR generator, verification loop"
```

---

## PHASE D: SENTINEL (24/7 Monitoring)

### D1. Sentinel Runtime (`tools/src/sentinel_runtime.rs`)
El motor que ejecuta el Sentinel Hand cada 5 minutos:
- `SentinelRuntime` struct con: baseline_metrics (rolling 24h), threat_intelligence (known bad IPs, attack patterns), alert_history
- `run_cycle()`:
  1. Ingiere logs del target (leer desde archivo, API, o stdout redirect)
  2. Parsea cada línea de log en `LogEntry` struct: timestamp, ip, method, path, status_code, user_agent, response_time_ms, body_size
  3. Ejecuta pattern matching contra la signature database del SKILL.md del sentinel (SQLi patterns, XSS patterns, scanner user agents, etc.)
  4. Calcula anomalías comparando con el baseline: request rate, error rate, response time, auth failure rate
  5. Clasifica threats: CRITICAL/HIGH/MEDIUM/LOW
  6. Para CRITICAL/HIGH: trigger incident-responder via inter-agent communication
  7. Para MEDIUM: envía alerta a Telegram
  8. Actualiza baseline con los datos de este ciclo
- `BaselineMetrics`: requests_per_minute_avg, requests_per_minute_stddev, error_rate_avg, p95_response_time, auth_failures_per_hour, unique_ips_per_hour
- `ThreatEvent`: timestamp, source_ip, threat_type, severity, matched_pattern, raw_log_entry, correlation_id

### D2. Telegram Alerting (`tools/src/telegram_alert.rs`)
Envía alertas formateadas a Telegram:
- `send_alert(bot_token, chat_id, alert: &ThreatAlert) -> Result<(), String>`
- `ThreatAlert`: severity, title, description, source_ip, affected_endpoint, timestamp, correlation_id, recommended_action
- Formato del mensaje en Telegram:
  ```
  🔴 CRITICAL THREAT DETECTED
  
  Type: SQL Injection Attempt
  Source: 185.234.xx.xx
  Target: /api/users/search
  Time: 2026-03-16 16:30:00 UTC
  
  Pattern matched: UNION SELECT in query parameter
  
  Action: Incident Responder triggered
  Correlation ID: abc-123-def
  ```
- Usar la API de Telegram Bot: POST https://api.telegram.org/bot{token}/sendMessage
- Para CRITICAL: agregar emoji 🔴, para HIGH: 🟠, MEDIUM: 🟡, LOW: 🔵

### D3. Incident Response Engine (`tools/src/incident_engine.rs`)
Motor de respuesta automática a incidentes:
- `IncidentEngine` struct con: active_incidents, containment_actions, forensic_logs
- `respond_to_threat(threat: ThreatEvent) -> IncidentResponse`:
  1. Verificar que no es false positive (revisar historial del IP, correlacionar con otros eventos)
  2. Clasificar el tipo de ataque
  3. Ejecutar containment según tipo:
     - SQLi/XSS/SSRF: bloquear IP via iptables o WAF rule (`iptables -A INPUT -s {ip} -j DROP`)
     - Brute force: bloquear IP range /24, lock targeted accounts
     - DDoS: activar rate limiting agresivo
     - Scanning: rate limit al IP, loguear todo
  4. Generar forensic snapshot: todos los logs del IP atacante, queries ejecutadas, response times
  5. Si el ataque explotó una vuln nueva (no en el reporte previo): trigger mini Phase 1→2
  6. Generar IncidentReport y enviarlo a Telegram
- `IncidentResponse`: incident_id, severity, status (contained/mitigated/resolved), actions_taken Vec<String>, forensic_data, requires_human bool

### D4. Dependency Monitor (`tools/src/dep_monitor.rs`)
Motor del dep-guardian Hand:
- `run_dependency_check(repo_path) -> DepCheckResult`:
  1. Ejecutar dep_audit tool contra el repo
  2. Comparar resultados con el último check (leer de knowledge_store)
  3. Identificar NUEVAS vulnerabilidades (que no existían en el check anterior)
  4. Para cada nueva vuln:
     - Si hay patch disponible sin breaking changes: crear branch, actualizar, run tests, crear PR
     - Si hay patch con breaking changes: crear PR con flag "needs-review"
     - Si no hay patch: alertar por Telegram
  5. Guardar resultados en knowledge_store para el próximo ciclo
- `DepCheckResult`: total_deps, new_vulns Vec<DepVuln>, auto_patched Vec<String>, needs_review Vec<String>

### D5. Continuous Loop Controller (`tools/src/continuous_loop.rs`)
Conecta Phase 3 de vuelta a Phase 1→2:
- `ContinuousLoopController`:
  - Escucha eventos del Sentinel y del Incident Engine
  - Cuando detecta una nueva vulnerabilidad (no en el reporte original):
    1. Trigger Phase 1 scan enfocado en el vector de ataque específico (no full scan)
    2. Esperar resultado
    3. Si confirma vuln nueva: trigger Phase 2 remediation enfocada
    4. Verificar fix
    5. Si fix exitoso: crear emergency PR, alertar "auto-patched"
    6. Si fix falla: escalar a humano via Telegram
  - Rate limit: máximo 1 mini-cycle cada 30 minutos para evitar loops infinitos
  - Mantener un log de todos los cycles ejecutados

### D6. Wire Sentinel components
- Agrega todos los módulos nuevos a `lib.rs`
- Registra tools: `run_sentinel_cycle`, `send_telegram_alert`, `respond_to_incident`, `check_dependencies`, `trigger_focused_scan`
- Actualiza los HAND.toml si necesitan nuevos tools en su allowlist

### D7. COMMIT
```
git add -A
git commit -m "Phase D: Sentinel — 24/7 monitoring, Telegram alerting, incident response, dependency guardian, continuous loop"
```

---

## PHASE E: PRODUCTION HARDENING

### E1. CLI Onboarding (`tools/src/cli.rs`)
Crea un CLI wrapper para onboarding fácil:
- `shieldagi connect <repo-url>` — one-command que:
  1. Clona el repo
  2. Detecta frameworks
  3. Corre Phase 1 completa
  4. Corre Phase 2 completa
  5. Activa Phase 3 monitoring
  6. Reporta resultados por Telegram
- `shieldagi status` — muestra estado actual de todos los agentes y hands
- `shieldagi scan <repo-url>` — solo Phase 1 (scan sin remediar)
- `shieldagi fix` — solo Phase 2 (remediar último reporte)
- `shieldagi sentinel start|stop|status` — controla Phase 3
- Implementar como funciones que orquestan los agents de OpenFang via `openfang agent spawn` y `openfang chat`

### E2. Configuration System (`tools/src/config.rs`)
Sistema de configuración centralizado:
- `ShieldConfig` struct que lee de `.env` y `shieldagi.toml`:
  - Target settings: repo_url, domain, ssh_key_path
  - Supabase settings: url, anon_key, service_key
  - GitHub settings: token, owner, repo
  - Notification settings: telegram_bot_token, telegram_chat_id, slack_webhook
  - Scan settings: max_duration, nmap_timeout, sqlmap_level, sqlmap_risk
  - Rate limit settings: auth_max, auth_window, api_max, api_window
  - Sentinel settings: interval_minutes, dep_check_hours
- `load_config(path) -> Result<ShieldConfig, String>`
- Validación: verificar que las API keys necesarias existen antes de arrancar

### E3. Self-Audit
Crea un script que ejecute ShieldAGI contra sí mismo:
- `tests/self-audit.sh`:
  1. Corre code-auditor contra el repo de ShieldAGI
  2. Corre header_audit contra el dashboard (si está corriendo)
  3. Corre secret_scan contra el repo
  4. Corre dep_audit contra todas las dependencias
  5. Reporta cualquier hallazgo
  6. Las herramientas propias de ShieldAGI NO deben tener vulnerabilidades

### E4. Documentation
Crea estos archivos de documentación:
- `docs/QUICK_START.md` — guía de 5 minutos para proteger un proyecto
- `docs/ARCHITECTURE.md` — diagrama y explicación de los 3 phases + todos los componentes
- `docs/AGENT_REFERENCE.md` — documentación de cada agente: qué hace, qué tools usa, cuándo se activa
- `docs/HAND_REFERENCE.md` — documentación de cada hand: schedule, métricas, configuración
- `docs/TOOL_REFERENCE.md` — documentación de cada tool: input schema, output format, ejemplo de uso
- `docs/CHAIN_WALLS.md` — guía de las chain walls: qué es cada wall, cómo configurar, cómo agregar custom walls
- `docs/PLAYBOOKS.md` — índice de todos los playbooks con links
- `docs/DEPLOYMENT.md` — guía completa de deploy en Hetzner AX102

### E5. Integration Tests Expansion
Expande el test suite en `tests/integration/`:
- `test_phase1_scan.sh` — verifica que Phase 1 encuentra todas las vulns en la vulnerable app
- `test_phase2_remediation.sh` — verifica que Phase 2 arregla todas las vulns
- `test_phase3_sentinel.sh` — verifica que Sentinel detecta ataques simulados
- `test_chain_walls.sh` — verifica que cada Chain Wall rechaza su tipo de ataque
- `test_end_to_end.sh` — pipeline completa: scan → fix → verify → monitor

### E6. Production Config Files
Crea archivos de configuración para producción:
- `deploy/docker-compose.production.yml` — stack completo para Hetzner: OpenFang + Grafana + Redis + PostgreSQL
- `deploy/nginx.conf` — reverse proxy con SSL para el dashboard
- `deploy/systemd/shieldagi.service` — systemd unit para auto-start
- `deploy/setup.sh` — script de instalación one-shot para un servidor nuevo:
  1. Instalar Docker
  2. Instalar OpenFang
  3. Configurar firewall (solo puertos 22, 80, 443, 4200)
  4. Copiar agents y hands
  5. Iniciar todo
  6. Verificar health

### E7. Final wiring
- Actualiza `README.md` con documentación completa, badges, quickstart actualizado
- Actualiza `CLAUDE_CODE_PROMPT.md` marcando TODAS las phases como completadas
- Verifica que `tools/src/lib.rs` tiene TODOS los módulos registrados y el dispatch cubre TODOS los tools
- Verifica que no hay warnings de compilación (`cargo clippy` si el Cargo.toml está configurado, o al menos revisa que el Rust sea válido)

### E8. FINAL COMMIT
```
git add -A
git commit -m "ShieldAGI 2.0 — Production Ready: CLI, config, self-audit, docs, deployment, integration tests"
```

---

## RESUMEN DE ARCHIVOS A CREAR

### Phase C (Remediation):
```
tools/src/report_types.rs
tools/src/framework_detect.rs
tools/src/remediation_pipeline.rs
tools/src/chain_walls_injector.rs
tools/src/pr_generator.rs
tools/src/verify_fix.rs
```

### Phase D (Sentinel):
```
tools/src/sentinel_runtime.rs
tools/src/telegram_alert.rs
tools/src/incident_engine.rs
tools/src/dep_monitor.rs
tools/src/continuous_loop.rs
```

### Phase E (Production):
```
tools/src/cli.rs
tools/src/config.rs
tests/self-audit.sh
tests/integration/test_phase1_scan.sh
tests/integration/test_phase2_remediation.sh
tests/integration/test_phase3_sentinel.sh
tests/integration/test_chain_walls.sh
tests/integration/test_end_to_end.sh
docs/QUICK_START.md
docs/ARCHITECTURE.md
docs/AGENT_REFERENCE.md
docs/HAND_REFERENCE.md
docs/TOOL_REFERENCE.md
docs/CHAIN_WALLS.md
docs/PLAYBOOKS.md
docs/DEPLOYMENT.md
deploy/docker-compose.production.yml
deploy/nginx.conf
deploy/systemd/shieldagi.service
deploy/setup.sh
```

### Archivos a MODIFICAR:
```
tools/src/lib.rs — agregar todos los módulos nuevos + tools al registry
tools/Cargo.toml — agregar dependencias nuevas si las necesitas
agents/shield-remediator/agent.toml — actualizar tool allowlist
hands/sentinel/HAND.toml — actualizar si necesita nuevos tools
hands/dep-guardian/HAND.toml — actualizar si necesita nuevos tools
hands/incident-responder/HAND.toml — actualizar si necesita nuevos tools
README.md — actualizar con docs completos
CLAUDE_CODE_PROMPT.md — marcar phases como completadas
```

---

## EJECUCIÓN

Empieza por Phase C, luego D, luego E. Haz commit después de cada phase. NO preguntes nada — si algo no está claro, toma la mejor decisión técnica y sigue adelante. El objetivo es que al terminar, ShieldAGI 2.0 sea una plataforma funcional completa que pueda escanear, arreglar, y proteger cualquier aplicación web de forma autónoma.

EMPIEZA AHORA.
