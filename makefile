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

PHONY: push
push:
	git add .
	git commit -m "update"
	git push

PHONY: pull
pull:
	git pull