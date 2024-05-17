PROGRAM_DIR = package/GitNinja
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
	python publish.py

clean:
	if exist "./build" rd /s /q build
	if exist "./$(DIST_DIR)" rd /s /q $(DIST_DIR)
	if exist "./$(PROGRAM_DIR).egg-info" rd /s /q $(PROGRAM_DIR).egg-info
	if exist "./*.spec" remove *.spec
	if exist "*.pyc __pycache__" rd /s /q *.pyc __pycache__
else
run:
	python3 $(PROGRAM_DIR)/$(PROGRAM_NAME).py

install: $(REQIUREMENTS)
	pip3 install -r $(REQIUREMENTS)

build: setup.py
	python3 setup.py build bdist_wheel

publish:
	python3 publish.py
	mkdir app
	mv $(DIST_DIR)/Ninja $(APP_DIR)/
	cp $(APP_DIR)/Ninja .
	echo "Saved into app directory"
	
obfuscate:
	pyarmor gen $(PROGRAM_DIR)/$(PROGRAM_NAME).py

releaseObfuscate:
	python3 publish.py
	mkdir app
	mv $(DIST_DIR)/Ninja $(APP_DIR)/
	cp $(APP_DIR)/Ninja .
	echo "Saved into app directory"

runObfuscate:
	python3 $(DIST_DIR)/$(PROGRAM_NAME).py

clean:
	rm -rf build
	rm -rf $(DIST_DIR)
	rm -rf $(PROGRAM_DIR).egg-info
	rm -rf *.spec
	rm -rf *.pyc __pycache__

cleanRelease:
	rm -rf build
	rm -rf app
	rm -rf Ninja
endif