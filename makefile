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

PHONY: clean
clean:
	rm -rf venv

PHONY: help
help:
	@echo "make activate-venv"
	@echo "make deactivate-venv"
	@echo "make test"
	@echo "make install"
	@echo "make run"
	@echo "make clean"
	@echo "make help"

# Path: .gitignore
venv
__pycache__