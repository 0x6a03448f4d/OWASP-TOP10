# OWASP Top 10 Lab Manager - Repository Reorganization Plan

## Vision
Transform from a functional lab manager into a world-class learning platform with:
- Clean architecture (platform vs content separation)
- Gamified labs with hints, validation, and completion screens
- Year-based organization showing vulnerability evolution (2017, 2021, 2025)

---

## Phase 1: Repository Reorganization

### Current Structure (Before)
```
📁 OWASP-TOP10/
├── OWASP-Web/            # Mixed with other categories
├── OWASP-API/
├── OWASP-Mobile/
├── OWASP-LLM/
├── src/                  # Backend code
├── index.html            # Frontend files in root
├── owasp-labs.html
├── nginx.conf
├── docker-compose.yml
├── cheat-sheets/         # Resources mixed in
├── diagrams/
├── compliance-mappings/
├── ctf-hub/              # Gamification in root
├── quiz-platform/
└── ...
```

### Target Structure (After)
```
📁 OWASP-TOP10/
├── 📁 platform/                    # The Lab Manager Engine
│   ├── 📁 backend/
│   │   ├── app.py
│   │   ├── requirements.txt
│   │   └── README.md
│   ├── 📁 frontend/
│   │   ├── index.html
│   │   ├── owasp-labs.html
│   │   ├── 📁 css/
│   │   ├── 📁 js/
│   │   │   └── year-config.js
│   │   └── 📁 assets/
│   └── 📁 infra/
│       ├── nginx.conf
│       ├── docker-compose.yml
│       ├── Dockerfile.lab-manager
│       └── README.md
│
├── 📁 labs/                        # Lab Content (Organized)
│   ├── 📁 base-images/             # Reusable gamification components
│   │   ├── 📁 nodejs-base/
│   │   ├── 📁 python-base/
│   │   └── README.md
│   ├── 📁 web/
│   │   ├── 📁 2017/
│   │   │   ├── A01-Injection/
│   │   │   ├── A02-Broken-Authentication/
│   │   │   └── ...
│   │   ├── 📁 2021/
│   │   │   ├── A01-Broken-Access-Control/
│   │   │   ├── A02-Cryptographic-Failures/
│   │   │   └── ...
│   │   └── 📁 2025/
│   ├── 📁 api/
│   │   ├── 📁 2019/
│   │   └── 📁 2023/
│   ├── 📁 mobile/
│   │   ├── 📁 2016/
│   │   └── 📁 2024/
│   └── 📁 llm/
│       └── 📁 2023/
│
├── 📁 resources/                   # Support Materials
│   ├── 📁 cheat-sheets/
│   ├── 📁 diagrams/
│   ├── 📁 compliance-mappings/
│   └── 📁 docs/
│
└── 📁 gamification/                # CTF and Quizzes
    ├── 📁 ctf-hub/
    ├── 📁 quiz-platform/
    └── README.md
```

---

## Phase 2: Perfect Lab Template Architecture

### Lab Structure Example: `labs/web/2021/A01-Broken-Access-Control/`

```
📁 A01-Broken-Access-Control/
├── 📁 lab/                         # The vulnerable application
│   ├── 📁 app/                     # Application code
│   │   ├── server.js               # Main app
│   │   ├── package.json
│   │   └── ...
│   ├── docker-compose.yml          # Lab infrastructure
│   └── Dockerfile
│
├── 📁 solution/                    # Solution guide (for educators)
│   ├── walkthrough.md
│   └── exploit.py
│
├── lab-guide.json                  # Gamification metadata
├── README.md                       # Lab overview
└── 📁 assets/                      # Lab-specific resources
    ├── screenshots/
    └── diagrams/
```

### lab-guide.json Schema

```json
{
  "id": "web-2021-a01",
  "title": "A01: Broken Access Control",
  "year": 2021,
  "category": "web",
  "difficulty": "medium",
  "estimatedTime": "30-45 minutes",
  
  "story": {
    "context": "You've discovered an e-commerce platform with suspicious access control...",
    "mission": "Exploit the broken access control to access another user's account",
    "learning_objectives": [
      "Understand IDOR vulnerabilities",
      "Learn about horizontal privilege escalation",
      "Practice access control testing"
    ]
  },
  
  "hints": [
    {
      "level": 1,
      "title": "Where to Start",
      "content": "Inspect the user profile URLs. Notice anything predictable?"
    },
    {
      "level": 2,
      "title": "Parameter Manipulation",
      "content": "Try changing the user ID parameter in the URL. Can you access other users?"
    },
    {
      "level": 3,
      "title": "The Solution",
      "content": "Modify the userId parameter from your own ID to another user's ID to access their account"
    }
  ],
  
  "validation": {
    "type": "flag",
    "flag": "OWASP{br0k3n_4cc3ss_c0ntr0l_2021}",
    "flagLocation": "Find the flag in the admin user's profile page"
  },
  
  "completion": {
    "title": "🎉 Excellent Work!",
    "summary": "You successfully exploited the broken access control vulnerability!",
    "learned": [
      "How to identify IDOR vulnerabilities",
      "The importance of proper authorization checks",
      "How to test for horizontal privilege escalation"
    ],
    "nextSteps": [
      "Try the 2017 version to see how this vulnerability evolved",
      "Explore A02: Cryptographic Failures next",
      "Read the prevention guide in resources"
    ],
    "resources": [
      "/resources/cheat-sheets/access-control.md",
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ]
  }
}
```

### Gamification UI Components

**Hint Panel** (Floating sidebar injected into lab):
```javascript
// Injected via base-image
class HintPanel {
  constructor(labGuide) {
    this.labGuide = labGuide;
    this.hintsRevealed = 0;
  }
  
  render() {
    // Creates floating panel in corner
    // Shows: Mission, Hints (progressively), Flag submission
  }
  
  revealHint(level) {
    // Reveals next hint
    // Tracks hint usage for scoring
  }
  
  validateFlag(userInput) {
    // Checks if flag is correct
    // Shows completion screen if valid
  }
}
```

---

## Implementation Steps

### Step 1: Create New Structure (Directories)
```bash
# Create platform structure
mkdir -p platform/backend
mkdir -p platform/frontend/{css,js,assets}
mkdir -p platform/infra

# Create labs structure
mkdir -p labs/base-images
mkdir -p labs/web/{2017,2021,2025}
mkdir -p labs/api/{2019,2023}
mkdir -p labs/mobile/{2016,2024}
mkdir -p labs/llm/2023

# Create resources structure
mkdir -p resources/{cheat-sheets,diagrams,compliance-mappings,docs}

# Create gamification structure
mkdir -p gamification/{ctf-hub,quiz-platform}
```

### Step 2: Move Existing Files
```bash
# Backend
mv src/lab-manager/* platform/backend/
mv Dockerfile.lab-manager platform/infra/

# Frontend
mv index.html platform/frontend/
mv owasp-labs.html platform/frontend/
mv src/web-assets/* platform/frontend/js/

# Infrastructure
mv nginx.conf platform/infra/
mv docker-compose.yml platform/infra/

# Labs (current structure - to be reorganized by year later)
# For now, keep in place and document migration path

# Resources
mv cheat-sheets/* resources/cheat-sheets/
mv diagrams/* resources/diagrams/
mv compliance-mappings/* resources/compliance-mappings/
mv docs/* resources/docs/

# Gamification
mv ctf-hub/* gamification/ctf-hub/
mv quiz-platform/* gamification/quiz-platform/
```

### Step 3: Update Paths in Code

**Files to update**:
- `platform/infra/docker-compose.yml` - Update volume mounts
- `platform/infra/nginx.conf` - Update root paths
- `platform/backend/app.py` - Update LAB_BASE_DIRECTORIES
- `platform/frontend/owasp-labs.html` - Update API endpoints

### Step 4: Create Base Images

Example: `labs/base-images/nodejs-base/`
```dockerfile
FROM node:18-alpine

# Install gamification UI components
COPY gamification-ui /usr/local/lib/gamification-ui

# Set up environment
ENV GAMIFICATION_ENABLED=true

# ... base setup
```

### Step 5: Create Example Lab Template

Create `labs/web/2021/A01-Broken-Access-Control/` with:
- Vulnerable app with access control issues
- lab-guide.json with full gamification
- Hint panel integration
- Flag validation
- Completion screen

---

## Benefits of New Structure

✅ **Separation of Concerns**: Platform code separate from content  
✅ **Scalability**: Easy to add new years and categories  
✅ **Maintainability**: Clear organization, easier to find files  
✅ **Collaboration**: Different teams can work on platform vs labs  
✅ **Evolution**: Can show how vulnerabilities changed over years  
✅ **Gamification**: Structured approach to hints and validation  
✅ **Professionalism**: Matches industry-standard project structures  

---

## Migration Strategy

**Approach**: Gradual migration without breaking current functionality

1. **Phase 1A**: Create new structure, move platform files
2. **Phase 1B**: Update paths, test platform works
3. **Phase 2A**: Create base-images and template
4. **Phase 2B**: Migrate one lab as proof-of-concept
5. **Phase 3**: Gradually migrate remaining labs
6. **Phase 4**: Remove old structure

**Note**: We can run both old and new structures in parallel during migration.

---

## Next Steps

1. Review and approve this plan
2. Execute Phase 1A (structure creation)
3. Execute Phase 1B (file moves and path updates)
4. Test that platform still works
5. Move to Phase 2 (gamification)

---

*This reorganization will transform the project from "it works" to "world-class learning platform"* 🚀
