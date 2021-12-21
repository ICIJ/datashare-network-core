CURRENT_VERSION ?= `pipenv run python setup.py --version`

clean:
		find . -name "*.pyc" -exec rm -rf {} \;
		rm -rf dist *.egg-info __pycache__

install: install_pip

install_pip:
		pipenv install -d

test:
		pipenv run nosetests

minor:
		pipenv run bumpversion --commit --tag --current-version ${CURRENT_VERSION} minor dsnet/__init__.py

major:
		pipenv run bumpversion --commit --tag --current-version ${CURRENT_VERSION} major dsnet/__init__.py

patch:
		pipenv run bumpversion --commit --tag --current-version ${CURRENT_VERSION} patch dsnet/__init__.py

distribute:
		pipenv run python setup.py sdist bdist_wheel
		pipenv run twine upload dist/*
