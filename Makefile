CURRENT_VERSION ?= `poetry version -s`
SEMVERS := major minor patch

clean:
		find . -name "*.pyc" -exec rm -rf {} \;
		rm -rf dist *.egg-info __pycache__

dist:
		poetry build

install: poetry_install

poetry_install:
		poetry install

tests:
		poetry run pytest

test-watch:
		poetry run pytest-watch

tag_version: 
		git commit -m "build: bump to ${CURRENT_VERSION}" pyproject.toml
		git tag ${CURRENT_VERSION}

$(SEMVERS):
		poetry version $@
		$(MAKE) tag_version
		
set_version:
		poetry version ${CURRENT_VERSION}
		$(MAKE) tag_version

distribute:
		poetry publish --build
		
show-updates:
		poetry show --latest --outdated