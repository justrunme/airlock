.PHONY: lint test check install clean

install:
	pip install -e ".[dev]"

lint:
	ruff check airlock tests
	ruff format --check airlock tests

format:
	ruff format airlock tests

test:
	pytest tests/ -v

test-all:
	pytest tests/ -v -m ""

check: lint test

clean:
	rm -rf build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
