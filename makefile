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
get_access_token:
	@echo "Fetching access token..."
	response=$(curl -X POST 'http://localhost:54321/auth/v1/token?grant_type=password' \
	-H "apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSJ9.vI9obAHOGyVVKa3pD--kJlyxp-Z2zV9UUMAhKpNLAcU" \
	-H "Content-Type: application/json" \
	-d '{
	  "email": "supa_admn@empylo.com",
	  "password": "super_admin_pswd"
	}')
	access_token=$(echo $response | jq -r '.access_token')
	echo "Access token: $access_token"