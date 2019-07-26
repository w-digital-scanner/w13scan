SRC_DIR = W13SCAN
MAKE = make


.PHONY: prebuildclean install build pypimeta pypi buildupload test flake8 clean


prebuildclean:
	@+python -c "import shutil; shutil.rmtree('build', True)"
	@+python -c "import shutil; shutil.rmtree('dist', True)"
	@+python -c "import shutil; shutil.rmtree('w13scan.egg-info', True)"


build:
	@make prebuildclean
	python3 setup.py sdist --formats=zip bdist_wheel

pypimeta:
	twine register

pypi:
	twine upload dist/*

buildupload:
	@make build
	#@make pypimeta
	@make pypi

clean:
	rm -rf *.egg-info dist build .tox
	find $(SRC_DIR) tests -type f -name '*.pyc' -delete