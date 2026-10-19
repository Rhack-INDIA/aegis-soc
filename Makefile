.PHONY: install corpus run test eval docker clean

install:
	python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt

corpus:
	python3 lab/gen_corpus.py

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

test:
	python -m pytest

eval:
	python3 scripts/eval.py

docker:
	docker build -t aegis-soc:latest .
	docker run --rm -p 8080:8080 -e STORE=sqlite -e SQLITE_PATH=/tmp/aegis.db aegis-soc:latest

clean:
	rm -rf data/aegis.db data/eval.db .venv __pycache__ app/__pycache__
