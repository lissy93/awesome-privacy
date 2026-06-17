
#########################################################################
# Welcome to Awesome Privacy!                                           #
# This file contains all the commands for the project (in lib and web)  #
#                                                                       #
# lib commands:                                                         #
# make install_lib_deps - Install Python dependencies for lib/          #
# make validate - Validates awesome-privacy.yml against the schema      #
# make gen_readme - Generate README.md from awesome-privacy.yml         #
#                                                                       #
# web commands:                                                         #
# make install_web_deps - Install NPM dependencies for the website      #
# make build_web - Build the static website (outputs to web/dist/)      #
# make start_web - Starts a webserver to serve the static website       #
#                                                                       #
# For further documentation, please reference the GitHub repository.    #
# https://github.com/lissy93/awesome-privacy or awesome-privacy.xyz     #
#                                                                       #
#########################################################################
# Licensed under CC0-1.0 (C) Alicia Sykes <https://aliciasykes.com>     #
#########################################################################

# Targets
.PHONY: all \
    install_lib_deps gen_readme gen_changelog validate review review_diff lib \
    install_web_deps build_web start_web web

# Get Python bin
PYTHON := $(shell which python3 2>/dev/null || which python)

# Directory Locations
LIB_DIR := lib
WEB_DIR := web

# Targets for lib/
install_lib_deps:
	$(PYTHON) -m pip install -q -r $(LIB_DIR)/requirements.txt

gen_readme: install_lib_deps
	$(PYTHON) $(LIB_DIR)/awesome-privacy-readme-gen.py

validate: install_lib_deps
	$(PYTHON) $(LIB_DIR)/validate-awesome-privacy.py

gen_changelog: install_lib_deps
	$(PYTHON) $(LIB_DIR)/generate-changelog.py

review: install_lib_deps
	$(PYTHON) $(LIB_DIR)/review-listings.py $(ARGS)

review_diff: install_lib_deps
	$(PYTHON) $(LIB_DIR)/review-listings.py --changed-since $(or $(BASE),main) $(ARGS)

lib: install_lib_deps validate gen_readme gen_changelog

# Targets for web/
install_web_deps:
	cd $(WEB_DIR) && yarn install

build_web: install_web_deps
	cd $(WEB_DIR) && yarn build

start_web: build_web
	cd $(WEB_DIR) && yarn start

dev_web: install_web_deps
	cd $(WEB_DIR) && yarn dev

web: install_web_deps build_web start_web
