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
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Run the self-test using virtual environment
venv/bin/python self_test.py "$@"

# Check exit code
if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}✓ Python SDK self-test completed successfully${NC}"
else
    echo -e "\n${RED}✗ Python SDK self-test failed${NC}"
    exit 1
fi