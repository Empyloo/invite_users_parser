activate-venv:
	source venv/bin/activate
	pip install --upgrade pip
	pip install -r requirements.txt

deactivate-venv:
	deactivate

PHONY: test
test:
	python -m pytest

PHONY: install
install:
	pip install -r requirements.txt

PHONY: run
run:
	python main.py
