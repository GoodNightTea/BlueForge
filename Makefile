# BlueForge Makefile
# Development automation and build tasks

.PHONY: help install install-dev clean test lint format docs run debug check requirements

# Default target
help:
	@echo "BlueForge Development Commands"
	@echo "=============================="
	@echo ""
	@echo "Setup and Installation:"
	@echo "  install      Install BlueForge for production use"
	@echo "  install-dev  Install BlueForge for development"
	@echo "  requirements Update requirements.txt"
	@echo ""
	@echo "Development:"
	@echo "  run          Run BlueForge in normal mode"
	@echo "  debug        Run BlueForge in debug mode"
	@echo "  test         Run test suite"
	@echo "  lint         Run code linting"
	@echo "  format       Format code with Black"
	@echo "  check        Run all checks (lint, test, format)"
	@echo ""
	@echo "Documentation:"
	@echo "  docs         Build documentation"
	@echo "  docs-serve   Serve documentation locally"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean        Clean build artifacts"
	@echo "  clean-all    Clean everything including logs"

# Installation targets
install:
	pip install -r requirements.txt
	pip install .

install-dev:
	pip install -r requirements.txt
	pip install -e ".[dev,docs]"

requirements:
	pip-compile requirements.in
	pip-compile requirements-dev.in

# Development targets
run:
	python blueforge.py

debug:
	python blueforge.py --debug --verbose

test:
	python -m pytest tests/ -v

lint:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

format:
	black . --line-length=100
	isort . --profile black

mypy:
	mypy . --ignore-missing-imports

check: lint test mypy
	@echo "All checks passed!"

# Documentation targets
docs:
	cd docs && make html

docs-serve:
	cd docs/_build/html && python -m http.server 8000

docs-clean:
	cd docs && make clean

# Cleanup targets  
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	rm -rf build/
	rm -rf dist/

clean-all: clean
	rm -rf logs/
	rm -rf sessions/
	rm -rf reports/
	rm -rf exports/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/

# Platform-specific setup
setup-linux:
	sudo apt-get update
	sudo apt-get install -y python3-dev bluez bluetooth
	sudo usermod -a -G bluetooth ${USER}
	@echo "Please log out and log back in for group changes to take effect"

setup-macos:
	brew install python
	@echo "Make sure Bluetooth is enabled in System Preferences"

setup-windows:
	@echo "Ensure Bluetooth is enabled and Python 3.8+ is installed"
	@echo "Run as Administrator if needed for BLE access"

# Docker targets
docker-build:
	docker build -t blueforge:latest .

docker-run:
	docker run -it --privileged --net=host blueforge:latest

docker-dev:
	docker run -it --privileged --net=host -v $(PWD):/app blueforge:latest /bin/bash

# Release targets
version:
	@python -c "import blueforge; print(f'BlueForge v{blueforge.__version__}')"

build:
	python setup.py sdist bdist_wheel

release: clean build
	@echo "Built BlueForge package in dist/"
	@echo "Run 'make publish' to upload to PyPI (if authorized)"

publish:
	twine upload dist/*

# Security and validation
security-scan:
	bandit -r . -f json -o security-report.json
	safety check

validate-config:
	python -c "from config import get_config_manager; cm = get_config_manager(); issues = cm.validate_config(); print('Config valid' if not issues else f'Issues: {issues}')"

# Performance profiling
profile:
	python -m cProfile -o profile.stats blueforge.py --check-only
	python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(20)"

# Utilities
count-lines:
	@echo "Code statistics:"
	@find . -name "*.py" -not -path "./venv/*" -not -path "./.venv/*" | xargs wc -l | tail -1

show-deps:
	pip list --format=freeze

show-tree:
	tree -I '__pycache__|*.pyc|.git|venv|.venv|build|dist|*.egg-info'

# Development server for web interface (if implemented)
serve:
	python -m blueforge.web.server --host 0.0.0.0 --port 8080

# Database and session management
reset-sessions:
	rm -rf sessions/*
	@echo "All sessions cleared"

backup-sessions:
	tar -czf sessions-backup-$(shell date +%Y%m%d_%H%M%S).tar.gz sessions/

# Git helpers
git-setup:
	git config --local core.hooksPath .githooks
	chmod +x .githooks/*

# Quick development workflow
dev-setup: install-dev setup-platform validate-config
	@echo "Development environment ready!"
	@echo "Run 'make run' to start BlueForge"

# Platform detection for setup
setup-platform:
ifeq ($(shell uname -s),Linux)
	@echo "Detected Linux - run 'make setup-linux' for system setup"
else ifeq ($(shell uname -s),Darwin)
	@echo "Detected macOS - run 'make setup-macos' for system setup"
else
	@echo "Detected Windows - run 'make setup-windows' for system setup"
endif

# Info target
info:
	@echo "BlueForge Development Environment"
	@echo "================================"
	@echo "Platform: $(shell uname -s)"
	@echo "Python: $(shell python --version 2>&1)"
	@echo "Working Directory: $(PWD)"
	@echo "Git Branch: $(shell git branch --show-current 2>/dev/null || echo 'Not a git repo')"
	@echo ""
	@make version