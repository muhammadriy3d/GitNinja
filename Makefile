PROGRAM_DIR = GitNinja
PROGRAM_NAME = git_ninja
DIST_DIR = dist
APP_DIR = app
RELEASE_DIR = $(APP_DIR)/release
REQIUREMENTS = requirements.txt

ifeq ($(OS), WINDOWS_NT)
run:
	python $(PROGRAM_DIR)/$(PROGRAM_NAME).py

install: requirements.txt
	pip install -r $(REQIUREMENTS)

build: setup.py
	python setup.py build bdist_wheel

publish:
	python publish
clean:
	if exist "./build" rd /s /q build
	if exist "./dist" rd /s /q dist
	if exist "./$(PROGRAM_DIR).egg-info" rd /s /q $(PROGRAM_DIR).egg-info
	if exist "./*.spec" remove *.spec
	if exist "*.pyc __pycache__" rd /s /q *.pyc __pycache__
else
run:
	python3 $(PROGRAM_DIR)/$(PROGRAM_NAME).py

install: requirements.txt
	pip3 install -r requirements.txt

build: setup.py
	python3 setup.py build bdist_wheel

publish:
	pyinstaller --onefile $(PROGRAM_DIR)/$(PROGRAM_NAME).py
	
obfuscate:
	pyarmor gen $(PROGRAM_DIR)/$(PROGRAM_NAME).py
	mkdir app

releaseObfuscate:
	pyinstaller --onefile dist/$(PROGRAM_NAME).py

runObfuscate:
	python3 dist/$(PROGRAM_NAME).py

clean:
	rm -rf build
	rm -rf dist
	rm -rf $(PROGRAM_DIR).egg-info
	rm -rf *.spec
	rm -rf *.pyc __pycache__

cleanRelease:
	rm -rf build
	
endif