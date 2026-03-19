.PHONY: help install install-dev test test-cov lint format clean build docker-build docker-run docker-stop docker-clean

# Default target
help:
	@echo "Argus - Information Gathering & Reconnaissance Toolkit"
	@echo ""
	@echo "Available commands:"
	@echo "  install      - Install Argus and dependencies"
	@echo "  install-dev  - Install Argus with development dependencies"
	@echo "  test         - Run tests"
	@echo "  test-cov     - Run tests with coverage"
	@echo "  lint         - Run linting checks"
	@echo "  format       - Format code with black and isort"
	@echo "  clean        - Clean build artifacts"
	@echo "  build        - Build package"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Argus in Docker"
	@echo "  docker-stop  - Stop Docker container"
	@echo "  docker-clean - Clean Docker artifacts"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev,full]"

# Testing
test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=argus --cov-report=html --cov-report=term-missing

# Code quality
lint:
	flake8 argus/ tests/
	bandit -r argus/
	mypy argus/

format:
	black argus/ tests/
	isort argus/ tests/

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

# Building
build:
	python -m build

# Docker operations
docker-build:
	docker build -t argus-recon:latest .

docker-run:
	docker run -it --rm \
		-v $(PWD)/results:/app/results \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/logs:/app/logs \
		--network host \
		argus-recon:latest

docker-run-interactive:
	docker run -it --rm \
		-v $(PWD)/results:/app/results \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/logs:/app/logs \
		--network host \
		argus-recon:latest bash

docker-compose-up:
	docker-compose up -d

docker-compose-down:
	docker-compose down

docker-clean:
	docker system prune -f
	docker image prune -f

# Development shortcuts
dev-setup: install-dev
	@echo "Development environment setup complete!"

quick-test: format lint test
	@echo "Quick test cycle complete!"

# Security checks
security-check:
	bandit -r argus/ -f json -o bandit-report.json
	safety check

# Documentation
docs-build:
	sphinx-build -b html docs/ docs/_build/html

docs-serve:
	cd docs/_build/html && python -m http.server 8000

# Release preparation
release-check: clean format lint test security-check
	@echo "Release checks complete!"

# Environment setup
setup-env:
	python -m venv venv
	@echo "Virtual environment created. Activate with: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)"

# API key setup reminder
setup-api-keys:
	@echo "Remember to set up your API keys:"
	@echo "export VIRUSTOTAL_API_KEY='your_key_here'"
	@echo "export SHODAN_API_KEY='your_key_here'"
	@echo "export CENSYS_API_ID='your_id_here'"
	@echo "export CENSYS_API_SECRET='your_secret_here'"
	@echo "export GOOGLE_API_KEY='your_key_here'"
	@echo "export HIBP_API_KEY='your_key_here'"

