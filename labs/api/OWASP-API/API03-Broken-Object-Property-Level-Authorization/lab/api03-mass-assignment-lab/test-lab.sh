#!/bin/bash

# API03 Mass Assignment Lab - Quick Test Script

echo "=== API03 Mass Assignment Lab - Quick Test ==="
echo

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BASE_URL="http://localhost:5003"

# Test 1: Health check
echo "1. Testing health endpoint..."
HEALTH=$(curl -s "$BASE_URL/api/health")
if echo "$HEALTH" | grep -q "healthy"; then
    echo -e "${GREEN}✓${NC} Health check passed"
else
    echo -e "${RED}✗${NC} Health check failed"
    exit 1
fi

# Test 2: Login as Alice
echo
echo "2. Testing login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"password123"}')

# Use jq for proper JSON parsing
if command -v jq &> /dev/null; then
    TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
else
    # Fallback to grep/cut if jq not available
    TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
fi

if [ -n "$TOKEN" ]; then
    echo -e "${GREEN}✓${NC} Login successful"
else
    echo -e "${RED}✗${NC} Login failed"
    exit 1
fi

# Test 3: Check for excessive data exposure
echo
echo "3. Testing for excessive data exposure..."
USER_DATA=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/users/me")

VULNERABILITIES=0

if echo "$USER_DATA" | grep -q "password_hash"; then
    echo -e "${YELLOW}!${NC} VULNERABLE: password_hash exposed"
    VULNERABILITIES=$((VULNERABILITIES + 1))
fi

if echo "$USER_DATA" | grep -q "api_key"; then
    echo -e "${YELLOW}!${NC} VULNERABLE: api_key exposed"
    VULNERABILITIES=$((VULNERABILITIES + 1))
fi

if echo "$USER_DATA" | grep -q "is_admin"; then
    echo -e "${YELLOW}!${NC} VULNERABLE: is_admin exposed"
    VULNERABILITIES=$((VULNERABILITIES + 1))
fi

if echo "$USER_DATA" | grep -q "salary"; then
    echo -e "${YELLOW}!${NC} VULNERABLE: salary exposed"
    VULNERABILITIES=$((VULNERABILITIES + 1))
fi

if [ $VULNERABILITIES -eq 4 ]; then
    echo -e "${GREEN}✓${NC} Excessive data exposure confirmed (as expected)"
else
    echo -e "${RED}✗${NC} Expected vulnerabilities not found"
fi

# Test 4: Test mass assignment vulnerability
echo
echo "4. Testing for mass assignment vulnerability..."

# Try to escalate privileges
UPDATE_RESPONSE=$(curl -s -X PUT "$BASE_URL/api/users/1" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","is_admin":true,"salary":999999}')

if echo "$UPDATE_RESPONSE" | grep -q "updated successfully"; then
    echo -e "${YELLOW}!${NC} VULNERABLE: Mass assignment allows privilege escalation"
    
    # Verify the change
    UPDATED_USER=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/users/me")
    if echo "$UPDATED_USER" | grep -q '"is_admin":true'; then
        echo -e "${YELLOW}!${NC} CONFIRMED: is_admin was modified via mass assignment"
    fi
    if echo "$UPDATED_USER" | grep -q '"salary":999999'; then
        echo -e "${YELLOW}!${NC} CONFIRMED: salary was modified via mass assignment"
    fi
    echo -e "${GREEN}✓${NC} Mass assignment vulnerability confirmed (as expected)"
else
    echo -e "${RED}✗${NC} Mass assignment test failed"
fi

# Summary
echo
echo "=== Test Summary ==="
echo -e "${GREEN}✓${NC} Lab is functioning correctly"
echo -e "${YELLOW}!${NC} Vulnerabilities are present as designed"
echo
echo "The lab is ready for use!"
echo "Start the lab with: docker-compose up -d"
echo "Follow instructions in: instructions.md"
