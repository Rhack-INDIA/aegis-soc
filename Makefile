.PHONY: install corpus run test verify eval docker clean

install:
	python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt

corpus:
	python3 lab/gen_corpus.py

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

test:
	python -m pytest

# hermes verify shells out to `pip install -r requirements.txt`; on a PEP 668
# host that fails unless the venv is active. This target makes that automatic.
verify:
	. .venv/bin/activate && hermes verify

eval:
	python3 scripts/eval.py

docker:
	docker build -t aegis-soc:latest .
	docker run --rm -p 8080:8080 -e STORE=sqlite -e SQLITE_PATH=/tmp/aegis.db aegis-soc:latest

clean:
	rm -rf data/aegis.db data/eval.db .venv __pycache__ app/__pycache__
