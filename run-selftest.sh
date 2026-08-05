#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Running Python SDK Self-Test${NC}"
echo "================================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi
source venv/bin/activate

# Sync dependencies on EVERY run, not only when the venv is first created.
#
# `pip install` used to live inside the creation branch, so an existing venv was never
# updated. Raising a floor in requirements.txt therefore had no effect on any machine that
# had already run this script once — the self-test, and the cross-SDK gauntlet that drives
# it, kept exercising whatever was installed months ago and reported green over it. That is
# a false green about the very thing the change was meant to fix: this venv still held
# aiohttp 3.14.1 and cryptography 49.0.0 while requirements.txt had moved past both.
# Re-resolving costs a second or two when already satisfied; a stale green costs more.
pip install -q --upgrade -r requirements.txt

# Run the self-test using virtual environment
venv/bin/python self_test.py "$@"

# Check exit code
if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}✓ Python SDK self-test completed successfully${NC}"
else
    echo -e "\n${RED}✗ Python SDK self-test failed${NC}"
    exit 1
fi