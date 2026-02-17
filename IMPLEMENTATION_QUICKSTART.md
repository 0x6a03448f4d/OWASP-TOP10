# Implementation Quick Start Guide

**When you're ready to begin the transformation to a world-class platform**

---

## Prerequisites

Before starting, ensure you have:
- ✅ Read `REORGANIZATION_PLAN.md`
- ✅ Read `LAB_TEMPLATE_GUIDE.md`
- ✅ Current platform is working correctly
- ✅ All changes committed to git
- ✅ Backup of current state created

---

## Phase 1: Repository Reorganization

### Step 1: Create New Directory Structure

Run these commands from the repository root:

```bash
# Create platform structure
mkdir -p platform/backend
mkdir -p platform/frontend/{css,js,assets}
mkdir -p platform/infra

# Create labs structure
mkdir -p labs/base-images/{nodejs-base,python-base}
mkdir -p labs/web/{2017,2021,2025}
mkdir -p labs/api/{2019,2023}
mkdir -p labs/mobile/{2016,2024}
mkdir -p labs/llm/2023

# Create resources structure
mkdir -p resources/{cheat-sheets,diagrams,compliance-mappings,docs}

# Create gamification structure
mkdir -p gamification/{ctf-hub,quiz-platform}

echo "✅ Directory structure created"
```

### Step 2: Move Platform Files

```bash
# Backend
cp -r src/lab-manager/* platform/backend/
cp Dockerfile.lab-manager platform/infra/

# Frontend
cp index.html platform/frontend/
cp owasp-labs.html platform/frontend/
cp -r src/web-assets/* platform/frontend/js/ 2>/dev/null || true

# Infrastructure
cp nginx.conf platform/infra/
cp docker-compose.yml platform/infra/

# Resources
cp -r cheat-sheets/* resources/cheat-sheets/ 2>/dev/null || true
cp -r diagrams/* resources/diagrams/ 2>/dev/null || true
cp -r compliance-mappings/* resources/compliance-mappings/ 2>/dev/null || true
cp -r docs/* resources/docs/ 2>/dev/null || true

# Gamification
cp -r ctf-hub/* gamification/ctf-hub/ 2>/dev/null || true
cp -r quiz-platform/* gamification/quiz-platform/ 2>/dev/null || true

echo "✅ Files copied to new structure"
```

### Step 3: Update Paths in Code

**File: `platform/infra/docker-compose.yml`**

Update volume mounts:
```yaml
# Before:
volumes:
  - ./src/lab-manager:/app

# After:
volumes:
  - ../../platform/backend:/app
```

**File: `platform/infra/nginx.conf`**

Update root paths:
```nginx
# Before:
root /usr/share/nginx/html;

# After:
root /usr/share/nginx/html/platform/frontend;
```

**File: `platform/backend/app.py`**

Update LAB_BASE_DIRECTORIES:
```python
# Before:
LAB_BASE_DIRECTORIES = [
    'OWASP-Web',
    'OWASP-API',
    'OWASP-Mobile',
    'OWASP-LLM'
]

# After:
LAB_BASE_DIRECTORIES = [
    '../../labs/web',
    '../../labs/api',
    '../../labs/mobile',
    '../../labs/llm'
]
```

### Step 4: Test Platform Still Works

```bash
cd platform/infra
docker-compose down
docker-compose up -d
docker-compose logs -f

# In another terminal:
curl http://localhost
# Should see the dashboard

curl http://localhost:4999/api/labs
# Should see labs list

echo "✅ Platform verified working with new structure"
```

---

## Phase 2: Create Gamification Template

### Step 1: Create Base Image

Create `labs/base-images/nodejs-base/Dockerfile`:

```dockerfile
FROM node:18-alpine

# Install gamification dependencies
RUN npm install -g http-server

# Copy gamification scripts
COPY gamification-ui.js /usr/local/lib/gamification-ui.js

# Set environment
ENV GAMIFICATION_ENABLED=true

WORKDIR /app
```

Create `labs/base-images/nodejs-base/gamification-ui.js`:

```javascript
// Copy the complete gamification.js code from LAB_TEMPLATE_GUIDE.md
// This will be injected into all labs
```

### Step 2: Create Example Lab

Create directory:
```bash
mkdir -p labs/web/2021/A01-Broken-Access-Control/{lab/app,solution,assets}
```

Create `labs/web/2021/A01-Broken-Access-Control/lab-guide.json`:
```json
{
  "id": "web-2021-a01-broken-access-control",
  "title": "A01: Broken Access Control",
  "year": 2021,
  // ... (copy full schema from LAB_TEMPLATE_GUIDE.md)
}
```

Create `labs/web/2021/A01-Broken-Access-Control/lab/app/server.js`:
```javascript
// Copy the vulnerable server code from LAB_TEMPLATE_GUIDE.md
```

Create `labs/web/2021/A01-Broken-Access-Control/lab/docker-compose.yml`:
```yaml
version: '3.8'
services:
  web:
    build:
      context: ./app
      dockerfile: Dockerfile
    ports:
      - "5011:3000"
    environment:
      - GAMIFICATION_ENABLED=true
    volumes:
      - ./app:/app
      - ../../base-images/nodejs-base/gamification-ui.js:/app/public/js/gamification.js
```

### Step 3: Test Example Lab

```bash
cd labs/web/2021/A01-Broken-Access-Control/lab
docker-compose up -d
docker-compose logs -f

# Open browser to http://localhost:5011
# Should see:
# 1. Vulnerable application
# 2. Gamification panel on right side
# 3. Mission, hints, flag submission

echo "✅ Example lab working with gamification"
```

---

## Phase 3: Migrate Existing Labs

### Migration Script Template

```bash
#!/bin/bash
# migrate-lab.sh
# Usage: ./migrate-lab.sh <category> <year> <vulnerability>

CATEGORY=$1  # web, api, mobile, llm
YEAR=$2      # 2017, 2021, 2025
VULN=$3      # A01-Broken-Access-Control

# Find old lab location
OLD_PATH=$(find OWASP-* -name "*${VULN}*" -type d | head -1)

if [ -z "$OLD_PATH" ]; then
  echo "❌ Lab not found"
  exit 1
fi

# Create new location
NEW_PATH="labs/${CATEGORY}/${YEAR}/${VULN}"
mkdir -p "$NEW_PATH"

# Copy lab
cp -r "$OLD_PATH"/* "$NEW_PATH/"

# Create lab-guide.json template
cat > "$NEW_PATH/lab-guide.json" <<EOF
{
  "id": "${CATEGORY}-${YEAR}-$(echo $VULN | tr '[:upper:]' '[:lower:]')",
  "title": "${VULN}",
  "year": ${YEAR},
  "category": "${CATEGORY}",
  "difficulty": "medium",
  "story": {
    "context": "TODO: Add context",
    "mission": "TODO: Add mission"
  },
  "hints": [],
  "validation": {
    "type": "flag",
    "flag": "OWASP{TODO}"
  }
}
EOF

echo "✅ Migrated ${OLD_PATH} -> ${NEW_PATH}"
echo "⚠️  Remember to:"
echo "   1. Update lab-guide.json"
echo "   2. Add gamification UI"
echo "   3. Test the lab"
```

### Migration Priority

**Week 1-2**: High-priority labs
- Web 2021: A01, A02, A03 (most common)
- API 2023: API01, API02
- Mobile 2024: M01

**Week 3-4**: Medium-priority
- Remaining Web 2021
- Remaining API 2023
- Remaining Mobile 2024

**Week 5+**: Everything else
- Historical versions (2017, 2019)
- LLM 2023
- Less common vulnerabilities

---

## Validation Checklist

After each phase, verify:

### Phase 1 Checklist
- [ ] New directories created
- [ ] Files copied correctly
- [ ] Paths updated in code
- [ ] Platform starts without errors
- [ ] Dashboard loads correctly
- [ ] API returns labs
- [ ] Individual labs can be started/stopped

### Phase 2 Checklist
- [ ] Base image builds successfully
- [ ] Example lab has lab-guide.json
- [ ] Gamification panel appears
- [ ] Hints can be revealed
- [ ] Flag can be submitted
- [ ] Completion screen shows

### Phase 3 Checklist (Per Lab)
- [ ] Lab copied to new location
- [ ] lab-guide.json created
- [ ] Gamification integrated
- [ ] Lab starts correctly
- [ ] Vulnerability still exploitable
- [ ] Flag validation works

---

## Troubleshooting

### Issue: Platform won't start after reorganization

**Check:**
1. Volume mounts in docker-compose.yml
2. File paths in nginx.conf
3. LAB_BASE_DIRECTORIES in app.py
4. Relative vs absolute paths

**Fix:**
```bash
# Check docker-compose logs
docker-compose logs

# Verify file locations
ls -la platform/backend/
ls -la platform/frontend/
```

### Issue: Gamification panel doesn't appear

**Check:**
1. gamification.js included in HTML
2. lab-guide.json accessible at /api/lab-guide
3. Browser console for errors
4. CORS settings

**Fix:**
```javascript
// Add to vulnerable app
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});
```

### Issue: Flag validation not working

**Check:**
1. Flag matches lab-guide.json exactly
2. /api/validate-flag endpoint exists
3. Case sensitivity setting
4. Network requests in browser DevTools

---

## Best Practices

### During Migration

1. **One at a time**: Migrate and test one lab before moving to next
2. **Keep old**: Don't delete old structure until migration complete
3. **Version control**: Commit after each successful migration
4. **Document**: Note any issues or workarounds
5. **Test thoroughly**: Each lab should be exploitable

### For New Labs

1. **Start with template**: Copy example lab structure
2. **Fill lab-guide.json first**: Complete all metadata
3. **Test hints**: Ensure they're progressive and helpful
4. **Validate flag location**: Flag should be findable but not obvious
5. **Write solution**: Document exploitation steps

### For Team Collaboration

1. **Assign categories**: Different team members for web/api/mobile/llm
2. **Review process**: Peer review lab-guide.json before migration
3. **Testing protocol**: Someone other than creator should test
4. **Documentation**: Keep notes on lessons learned
5. **Iteration**: Refine template based on feedback

---

## Success Criteria

You'll know the transformation is complete when:

✅ All platform files in `platform/` directory  
✅ All labs in `labs/` organized by category and year  
✅ All resources in `resources/` directory  
✅ At least 10 labs have full gamification  
✅ Template can be easily copied for new labs  
✅ Platform starts and works correctly  
✅ Students can complete gamified labs  
✅ Completion screens show meaningful summaries  

---

## Timeline Estimate

**Conservative**: 8 weeks
- Week 1-2: Phase 1 (Reorganization)
- Week 3-4: Phase 2 (Template)
- Week 5-8: Phase 3 (Migration)

**Aggressive**: 4 weeks
- Week 1: Phase 1
- Week 2: Phase 2
- Week 3-4: Phase 3 (partial)

**Realistic**: 6 weeks
- Week 1-2: Phase 1 + Phase 2
- Week 3-6: Phase 3 (gradual migration)

---

## Getting Help

If stuck:
1. Review `REORGANIZATION_PLAN.md`
2. Check `LAB_TEMPLATE_GUIDE.md` for examples
3. Look at successfully migrated labs
4. Test with simple lab first
5. Ask for code review

---

## Next Step

**Ready to begin?**

```bash
# Start with Phase 1, Step 1
mkdir -p platform/backend
# ... and continue with the commands above
```

**Take it slow, test frequently, and celebrate small wins!** 🎉

---

*From planning to execution - you've got this!* 💪
