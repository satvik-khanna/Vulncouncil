.PHONY: setup demo model memory test build evaluate infra down
setup:
	uv sync --cache-dir .cache/uv
	cd frontend && npm ci
infra:
	docker compose up -d --build slim lab-target
demo: build infra
	.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
model:
	docker compose -f docker-compose.yml -f docker-compose.model.yml --profile full up --build -d
memory: build
	.venv/bin/python scripts/start_memory.py
build:
	cd frontend && npm run build
test:
	.venv/bin/python -m pytest -q
evaluate:
	.venv/bin/python scripts/evaluate.py
down:
	docker compose --profile full down

