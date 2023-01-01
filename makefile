activate-venv:
	source venv/bin/activate

deactivate-venv:
	deactivate

PHONY: test
test:
	python -m pytest -vv

PHONY: install
install:
	pip install -r requirements.txt

PHONY: run
run:
	python main.py

PHONY: clean
clean:
	rm -rf venv
