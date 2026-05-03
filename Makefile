NAMESPACE  := security-audit
REGISTRY   ?= ghcr.io/Numberbis
IMAGE_TAG  ?= latest
ANSIBLE    := cd ansible && ansible-playbook

VENV       := venv_audit
PYTHON     := $(VENV)/bin/python
PIP        := $(VENV)/bin/pip
PYTEST     := $(VENV)/bin/pytest

.PHONY: help up down scan scan-tool scan-site scan-group report notify \
        bootstrap build push deploy update-targets trigger-scan status logs teardown \
        test test-unit test-integration test-setup test-clean \
        results results-test open-report \
        audit-now audit-now-html audit-quick open-audit \
        monitoring monitoring-down demo demo-reset \
        agent-up agent-logs agent-budget triage triage-all chat

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Docker Compose (local, no Kubernetes) ────────────────────────────────────

demo:  ## Démarrer le stack + charger des données de démo réalistes (idéal pour une démo rapide)
	docker compose up -d
	@echo "Attente du collector..."
	@until docker compose exec -T collector curl -sf http://localhost:8080/health > /dev/null 2>&1; do sleep 2; done
	docker compose --profile demo run --rm demo-seeder
	@echo ""
	@echo "  Dashboard avec données de démo : http://localhost:5000"

demo-reset:  ## Recharger les données de démo (efface et réinsère)
	docker compose --profile demo run --rm demo-seeder

up:  ## Start the full stack locally (postgres + collector + dashboard)
	docker compose up -d
	@echo ""
	@echo "  Dashboard : http://localhost:5000"
	@echo "  Collector : http://localhost:8080"

up-scheduler:  ## Start stack + automated notifier + report-generator
	docker compose --profile scheduler up -d

monitoring:  ## Démarrer Prometheus + Grafana (dashboard : http://localhost:3000)
	docker compose --profile monitoring up -d
	@echo ""
	@echo "  Grafana    : http://localhost:3000  (admin / \$$GRAFANA_ADMIN_PASSWORD)"
	@echo "  Prometheus : http://localhost:9090"

monitoring-down:  ## Arrêter le stack de monitoring
	docker compose --profile monitoring down

down:  ## Stop and remove all containers
	docker compose down

# ── Agent IA (triage, remédiation, chat) ─────────────────────────────────────

agent-up:  ## Démarrer le service Agent IA seul (postgres doit tourner)
	docker compose up -d agent
	@echo ""
	@echo "  Agent IA   : http://localhost:8090"
	@echo "  Health     : curl http://localhost:8090/health"
	@echo "  Budget     : curl http://localhost:8090/budget"

agent-logs:  ## Logs du service agent
	docker compose logs -f agent

agent-budget:  ## Vérifier le budget LLM consommé aujourd'hui
	@curl -s http://localhost:8090/budget | python3 -m json.tool

triage:  ## Triage IA d'un scan donné — SCAN_ID=42
	@test -n "$(SCAN_ID)" || (echo "Usage: make triage SCAN_ID=42" && exit 1)
	@curl -s -X POST http://localhost:8090/triage \
		-H "Content-Type: application/json" \
		-d '{"scan_id": $(SCAN_ID)}' | python3 -m json.tool

triage-all:  ## Triage IA de tous les scans complétés non encore triagés
	@$(PYTHON) scripts/triage-all.py 2>/dev/null || python3 scripts/triage-all.py

chat:  ## Question rapide à l'agent — Q="ta question"
	@test -n "$(Q)" || (echo "Usage: make chat Q=\"Combien de findings critiques ?\"" && exit 1)
	@curl -s -X POST http://localhost:8090/chat \
		-H "Content-Type: application/json" \
		-d '{"question": "$(Q)"}' | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("answer",""))'

scan:  ## Run all scanners against all sites in config/websites.yml
	bash scripts/scan-all.sh

scan-tool:  ## Run one tool against all sites — TOOL=nuclei
	bash scripts/scan-all.sh --tool $(TOOL)

scan-site:  ## Run all tools against one site — SITE=my-site
	bash scripts/scan-all.sh --site $(SITE)

scan-group:  ## Run all tools against a site group — GROUP=restaurants
	bash scripts/scan-all.sh --group $(GROUP)

report:  ## Generate HTML/PDF reports now (requires scheduler profile)
	docker compose --profile scheduler run --rm report-generator python generate.py

notify:  ## Send pending alerts now (requires scheduler profile)
	docker compose --profile scheduler run --rm notifier python notify.py

dc-logs:  ## Stream collector logs (local stack)
	docker compose logs -f collector

# ── Kubernetes / Ansible ─────────────────────────────────────────────────────

bootstrap:  ## Provision full Kubernetes infrastructure (Ansible)
	./scripts/bootstrap.sh

build:  ## Build toutes les images Docker
	@for tool in zap nikto nmap testssl nuclei observatory retirejs wpscan trivy collector report-generator notifier dashboard agent; do \
		echo "Building $$tool..."; \
		docker build -t $(REGISTRY)/argus-$$tool:$(IMAGE_TAG) docker/$$tool; \
	done

push:  ## Push toutes les images vers le registry
	@for tool in zap nikto nmap testssl nuclei observatory retirejs wpscan trivy collector report-generator notifier dashboard agent; do \
		docker push $(REGISTRY)/argus-$$tool:$(IMAGE_TAG); \
	done

deploy:  ## Applique tous les manifests k8s/
	kubectl apply -R -f k8s/ -n $(NAMESPACE)

update-targets:  ## Recharge les CronJobs depuis config/websites.yml
	$(ANSIBLE) playbooks/update-targets.yml

trigger-scan:  ## Scan manuel : make trigger-scan TOOL=zap TARGET=buildweb
	./scripts/trigger-scan.sh $(TOOL) $(TARGET)

status:  ## État de l'infrastructure dans Kubernetes
	./scripts/check-status.sh

logs:  ## Logs du collector
	kubectl logs -f deployment/collector -n $(NAMESPACE)

teardown:  ## Supprime toute l'infrastructure (DANGER)
	$(ANSIBLE) playbooks/teardown.yml -e confirm_teardown=true

# ── Tests ────────────────────────────────────────────────────────────────────

test-setup:  ## Installe les dépendances de test dans venv_audit
	$(PIP) install -r tests/requirements-test.txt

test-unit:  ## Lance les tests unitaires (sans base de données)
	@mkdir -p reports/tests
	$(PYTEST) tests/unit/ -v

test-integration:  ## Lance les tests d'intégration (nécessite docker compose)
	@mkdir -p reports/tests
	docker compose -f docker-compose.test.yml up -d
	INTEGRATION_TEST_DB_URL=postgresql://audit:test@localhost:5433/audit_test \
		$(PYTEST) tests/integration/ -v
	@echo "Base de test toujours active — lancez 'make test-clean' pour l'arrêter"

test:  ## Lance tous les tests (unitaires + intégration)
	$(MAKE) test-unit
	$(MAKE) test-integration

test-clean:  ## Supprime les conteneurs de test
	docker compose -f docker-compose.test.yml down -v --remove-orphans

audit-now:  ## Lance un audit de sécurité instantané sur tous les sites (terminal)
	$(PYTHON) scripts/audit-now.py

audit-now-html:  ## Génère un rapport HTML par site dans reports/  — TARGET=nom pour un seul site
	@bash scripts/generate-reports.sh $(if $(TARGET),$(TARGET),)

audit-quick:  ## Audit rapide sans Mozilla Observatory — TARGET=nom pour un seul site
	@bash scripts/generate-reports.sh --skip-observatory $(if $(TARGET),$(TARGET),)

open-audit:  ## Ouvre le dernier rapport d'audit HTML dans le navigateur
	@latest=$$(ls -t reports/audit-*.html 2>/dev/null | head -1); \
	if [ -n "$$latest" ]; then \
		xdg-open "$$latest" 2>/dev/null || open "$$latest" 2>/dev/null || echo "Rapport : $$latest"; \
	else \
		echo "Aucun rapport trouvé — lancez 'make audit-now-html' d'abord"; \
	fi

open-report:  ## Ouvre le dernier rapport HTML des tests dans le navigateur
	@test -f reports/tests/report.html \
		&& xdg-open reports/tests/report.html 2>/dev/null || open reports/tests/report.html 2>/dev/null \
		|| echo "Rapport disponible : reports/tests/report.html"

# ── Résultats des scans d'audit ───────────────────────────────────────────────

results:  ## Affiche les résultats des scans (base de prod) — TARGET= SEVERITY= LIMIT=
	$(PYTHON) scripts/show-audit-results.py \
		$(if $(TARGET),--target $(TARGET),) \
		$(if $(SEVERITY),--severity $(SEVERITY),) \
		$(if $(LIMIT),--limit $(LIMIT),)

results-test:  ## Affiche les résultats des scans (base de test) — TARGET= SEVERITY= LIMIT=
	@docker compose -f docker-compose.test.yml up -d postgresql-test db-init 2>/dev/null; \
	sleep 2
	DB_URL=postgresql://audit:test@localhost:5433/audit_test \
		$(PYTHON) scripts/show-audit-results.py \
		$(if $(TARGET),--target $(TARGET),) \
		$(if $(SEVERITY),--severity $(SEVERITY),) \
		$(if $(LIMIT),--limit $(LIMIT),)
