# Perfect Lab Template - Technical Guide

## Overview

This guide details the technical implementation of a "perfect lab" with gamification, hints, and validation - the foundation for world-class learning experiences.

---

## Example Lab: Web 2021 A01 - Broken Access Control

### Complete Lab Structure

```
labs/web/2021/A01-Broken-Access-Control/
├── lab/
│   ├── app/
│   │   ├── server.js                 # Express.js vulnerable app
│   │   ├── package.json
│   │   ├── public/
│   │   │   ├── index.html
│   │   │   ├── profile.html
│   │   │   ├── css/
│   │   │   │   └── style.css
│   │   │   └── js/
│   │   │       ├── app.js
│   │   │       └── gamification.js   # Hint panel integration
│   │   ├── data/
│   │   │   └── users.json            # Sample user database
│   │   └── routes/
│   │       ├── auth.js
│   │       ├── users.js
│   │       └── gamification.js       # Hint/flag API
│   ├── Dockerfile
│   └── docker-compose.yml
├── solution/
│   ├── walkthrough.md
│   ├── exploit.py
│   └── screenshots/
├── lab-guide.json                    # Gamification metadata
├── README.md
└── assets/
    ├── architecture.png
    └── vulnerability-diagram.png
```

---

## Component 1: lab-guide.json (Metadata)

Full example with all fields:

```json
{
  "id": "web-2021-a01-broken-access-control",
  "version": "1.0.0",
  "title": "A01: Broken Access Control",
  "subtitle": "Horizontal Privilege Escalation",
  "year": 2021,
  "category": "web",
  "owasp_ranking": "A01",
  
  "metadata": {
    "difficulty": "medium",
    "estimatedTime": "30-45 minutes",
    "prerequisites": [
      "Basic understanding of HTTP",
      "Familiarity with web authentication"
    ],
    "tags": ["idor", "access-control", "authorization", "privilege-escalation"],
    "cwe": ["CWE-639", "CWE-284"],
    "author": "OWASP Top 10 Lab Team",
    "lastUpdated": "2024-01-15"
  },
  
  "story": {
    "context": "You've been hired as a security consultant to test a new e-commerce platform called 'ShopSecure'. The development team claims their access controls are robust, but you suspect otherwise. The platform handles sensitive customer data including orders, payment information, and personal details.",
    
    "mission": "Your mission is to exploit the broken access control vulnerability to access another user's account information. Find the flag hidden in the admin user's profile to prove the vulnerability exists.",
    
    "scenario": "You have a normal user account (user ID: 1001). There's an admin account (user ID: 1000) that contains sensitive information. Can you access it without proper authorization?",
    
    "learning_objectives": [
      "Understand what IDOR (Insecure Direct Object Reference) vulnerabilities are",
      "Learn how to identify broken access control in web applications",
      "Practice horizontal privilege escalation techniques",
      "Understand the importance of proper authorization checks"
    ]
  },
  
  "environment": {
    "url": "http://localhost:${PORT}",
    "credentials": {
      "username": "testuser",
      "password": "testpass123",
      "userId": 1001
    },
    "adminCredentials": {
      "note": "You need to discover these through exploitation",
      "userId": 1000
    }
  },
  
  "hints": [
    {
      "level": 1,
      "title": "Observation",
      "category": "reconnaissance",
      "content": "After logging in, navigate to your profile page. Look carefully at the URL structure. What parameters do you see? Are they predictable?",
      "penalty": 5,
      "unlockAfter": 0
    },
    {
      "level": 2,
      "title": "Parameter Analysis",
      "category": "identification",
      "content": "The profile page URL contains a 'userId' parameter. Your user has ID 1001. What happens if you try to access user ID 1000? Does the application properly validate that you're authorized to view that profile?",
      "penalty": 10,
      "unlockAfter": 300
    },
    {
      "level": 3,
      "title": "Exploitation Technique",
      "category": "exploitation",
      "content": "Modify the userId parameter in the profile URL from 1001 to 1000. The application doesn't verify that the logged-in user matches the profile being requested. This is a classic IDOR vulnerability.",
      "penalty": 20,
      "unlockAfter": 600
    },
    {
      "level": 4,
      "title": "Complete Solution",
      "category": "solution",
      "content": "Navigate to http://localhost:${PORT}/profile?userId=1000 while logged in as your normal user. You'll see the admin's profile with the flag. This works because the backend only checks if you're authenticated, not if you're authorized to view that specific user's data.",
      "penalty": 30,
      "unlockAfter": 900
    }
  ],
  
  "validation": {
    "type": "flag",
    "flag": "OWASP{br0k3n_4cc3ss_c0ntr0l_1d0r_2021}",
    "flagFormat": "OWASP{[a-z0-9_]+}",
    "flagLocation": "The flag is visible in the admin user's (userId: 1000) profile page bio field",
    "attempts": 5,
    "caseInsensitive": true
  },
  
  "scoring": {
    "basePoints": 100,
    "timeBonus": {
      "under15min": 50,
      "under30min": 25,
      "under45min": 10
    },
    "hintPenalty": {
      "perHint": [5, 10, 20, 30]
    }
  },
  
  "completion": {
    "title": "🎉 Excellent Work! Vulnerability Exploited!",
    "message": "You successfully exploited the broken access control vulnerability! This is one of the most critical security issues in modern web applications.",
    
    "summary": {
      "vulnerability": "Insecure Direct Object Reference (IDOR)",
      "impact": "Horizontal privilege escalation allowing unauthorized access to other users' data",
      "cvss": "7.5 (High)",
      "realWorldExample": "In 2019, a major social media platform exposed 267 million user profiles through a similar IDOR vulnerability."
    },
    
    "whatYouLearned": [
      "How to identify predictable parameter patterns in URLs",
      "The difference between authentication and authorization",
      "How IDOR vulnerabilities allow horizontal privilege escalation",
      "The importance of validating user access to resources"
    ],
    
    "prevention": [
      "Implement proper authorization checks for every request",
      "Use indirect references (tokens) instead of direct database IDs",
      "Validate that the authenticated user has permission to access the requested resource",
      "Implement proper access control lists (ACLs)",
      "Use framework-level authorization middleware"
    ],
    
    "nextSteps": [
      {
        "title": "Compare with 2017",
        "description": "Check out the 2017 version of this vulnerability to see how the attack evolved",
        "link": "/labs/web/2017/A05-Broken-Access-Control"
      },
      {
        "title": "Try Vertical Escalation",
        "description": "This lab showed horizontal escalation. Try a vertical escalation challenge next",
        "link": "/labs/web/2021/A01-Broken-Access-Control-Vertical"
      },
      {
        "title": "Learn Prevention",
        "description": "Read the comprehensive prevention guide",
        "link": "/resources/cheat-sheets/access-control-prevention.md"
      }
    ],
    
    "resources": [
      {
        "title": "OWASP Access Control Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
        "type": "external"
      },
      {
        "title": "OWASP Top 10 2021 - A01",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "type": "external"
      },
      {
        "title": "Authorization Testing Guide",
        "url": "/resources/docs/authorization-testing.md",
        "type": "internal"
      }
    ],
    
    "badge": {
      "name": "Access Control Breaker",
      "image": "/assets/badges/access-control-breaker.svg",
      "description": "Completed A01: Broken Access Control"
    }
  },
  
  "feedback": {
    "enabled": true,
    "questions": [
      {
        "type": "rating",
        "question": "How would you rate the difficulty of this lab?",
        "scale": 5
      },
      {
        "type": "text",
        "question": "What did you find most helpful about this lab?"
      },
      {
        "type": "multiple_choice",
        "question": "Did the hints help you solve the lab?",
        "options": ["Very helpful", "Somewhat helpful", "Not helpful", "Didn't use hints"]
      }
    ]
  }
}
```

---

## Component 2: Gamification UI (Client-Side)

### gamification.js (Injected into Lab)

```javascript
/**
 * OWASP Lab Gamification System
 * Provides hints, validation, and completion screens
 */

class LabGamification {
  constructor(labGuideData) {
    this.labGuide = labGuideData;
    this.state = {
      hintsRevealed: [],
      attemptsRemaining: labGuideData.validation.attempts,
      startTime: Date.now(),
      completed: false
    };
    
    this.init();
  }
  
  init() {
    // Load saved state from localStorage
    this.loadState();
    
    // Inject gamification panel
    this.injectPanel();
    
    // Set up event listeners
    this.setupListeners();
    
    // Track time
    this.startTimer();
  }
  
  injectPanel() {
    const panel = document.createElement('div');
    panel.id = 'lab-gamification-panel';
    panel.className = 'lab-panel';
    panel.innerHTML = `
      <div class="panel-header">
        <h3>Lab Guide</h3>
        <button class="panel-toggle">−</button>
      </div>
      
      <div class="panel-content">
        <!-- Mission Tab -->
        <div class="tab-content" id="mission-tab">
          <h4>🎯 Mission</h4>
          <p>${this.labGuide.story.mission}</p>
          
          <h5>Learning Objectives:</h5>
          <ul>
            ${this.labGuide.story.learning_objectives.map(obj => 
              `<li>${obj}</li>`
            ).join('')}
          </ul>
          
          <div class="credentials">
            <h5>Test Credentials:</h5>
            <code>
              Username: ${this.labGuide.environment.credentials.username}<br>
              Password: ${this.labGuide.environment.credentials.password}
            </code>
          </div>
        </div>
        
        <!-- Hints Tab -->
        <div class="tab-content" id="hints-tab">
          <h4>💡 Hints</h4>
          <div class="hints-container">
            ${this.renderHints()}
          </div>
        </div>
        
        <!-- Validation Tab -->
        <div class="tab-content" id="validation-tab">
          <h4>🚩 Submit Flag</h4>
          <p>${this.labGuide.validation.flagLocation}</p>
          
          <div class="flag-input">
            <input type="text" 
                   id="flag-input" 
                   placeholder="Enter flag here..."
                   ${this.state.completed ? 'disabled' : ''}>
            <button id="submit-flag" 
                    ${this.state.completed ? 'disabled' : ''}>
              Submit
            </button>
          </div>
          
          <div class="attempts-remaining">
            Attempts remaining: ${this.state.attemptsRemaining}
          </div>
          
          ${this.state.completed ? '<div class="success-message">✅ Flag accepted!</div>' : ''}
        </div>
      </div>
      
      <style>
        .lab-panel {
          position: fixed;
          top: 20px;
          right: 20px;
          width: 350px;
          max-height: 80vh;
          background: white;
          border: 2px solid #007bff;
          border-radius: 8px;
          box-shadow: 0 4px 6px rgba(0,0,0,0.1);
          z-index: 9999;
          overflow-y: auto;
        }
        
        .panel-header {
          background: #007bff;
          color: white;
          padding: 15px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        
        .panel-toggle {
          background: none;
          border: none;
          color: white;
          font-size: 20px;
          cursor: pointer;
        }
        
        .panel-content {
          padding: 20px;
        }
        
        .hint-item {
          margin: 10px 0;
          padding: 10px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }
        
        .hint-locked {
          background: #f8f9fa;
          color: #999;
        }
        
        .hint-revealed {
          background: #e7f3ff;
        }
        
        .flag-input {
          display: flex;
          gap: 10px;
          margin: 15px 0;
        }
        
        .flag-input input {
          flex: 1;
          padding: 8px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }
        
        .flag-input button {
          padding: 8px 15px;
          background: #28a745;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
        
        .success-message {
          color: #28a745;
          font-weight: bold;
          margin-top: 10px;
        }
        
        .credentials {
          background: #f8f9fa;
          padding: 10px;
          border-radius: 4px;
          margin-top: 15px;
        }
        
        .credentials code {
          display: block;
          margin-top: 5px;
          font-size: 12px;
        }
      </style>
    `;
    
    document.body.appendChild(panel);
  }
  
  renderHints() {
    return this.labGuide.hints.map((hint, index) => {
      const isRevealed = this.state.hintsRevealed.includes(index);
      const canReveal = index === 0 || this.state.hintsRevealed.includes(index - 1);
      
      return `
        <div class="hint-item ${isRevealed ? 'hint-revealed' : 'hint-locked'}">
          <div class="hint-header">
            <strong>Hint ${index + 1}: ${hint.title}</strong>
            ${!isRevealed && canReveal ? 
              `<button class="reveal-hint" data-hint="${index}">
                Reveal (-${hint.penalty} pts)
              </button>` : ''}
          </div>
          <div class="hint-content">
            ${isRevealed ? hint.content : '🔒 Locked'}
          </div>
        </div>
      `;
    }).join('');
  }
  
  setupListeners() {
    // Toggle panel
    document.querySelector('.panel-toggle').addEventListener('click', () => {
      const content = document.querySelector('.panel-content');
      content.style.display = content.style.display === 'none' ? 'block' : 'none';
    });
    
    // Reveal hints
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('reveal-hint')) {
        const hintIndex = parseInt(e.target.dataset.hint);
        this.revealHint(hintIndex);
      }
    });
    
    // Submit flag
    document.getElementById('submit-flag')?.addEventListener('click', () => {
      const flagInput = document.getElementById('flag-input').value;
      this.validateFlag(flagInput);
    });
  }
  
  revealHint(index) {
    if (!this.state.hintsRevealed.includes(index)) {
      this.state.hintsRevealed.push(index);
      this.saveState();
      
      // Re-render hints
      document.querySelector('.hints-container').innerHTML = this.renderHints();
      this.setupListeners(); // Re-attach event listeners
    }
  }
  
  async validateFlag(userInput) {
    if (this.state.attemptsRemaining <= 0) {
      alert('No attempts remaining!');
      return;
    }
    
    const isCorrect = userInput.trim().toLowerCase() === 
                     this.labGuide.validation.flag.toLowerCase();
    
    if (isCorrect) {
      this.state.completed = true;
      this.state.endTime = Date.now();
      this.saveState();
      
      // Show completion screen
      this.showCompletionScreen();
    } else {
      this.state.attemptsRemaining--;
      this.saveState();
      alert(`Incorrect flag. ${this.state.attemptsRemaining} attempts remaining.`);
      
      // Update UI
      document.querySelector('.attempts-remaining').textContent = 
        `Attempts remaining: ${this.state.attemptsRemaining}`;
    }
  }
  
  showCompletionScreen() {
    const completion = this.labGuide.completion;
    const timeSpent = Math.round((this.state.endTime - this.state.startTime) / 1000 / 60);
    const hintsUsed = this.state.hintsRevealed.length;
    
    // Calculate score
    let score = this.labGuide.scoring.basePoints;
    
    // Time bonus
    if (timeSpent < 15 && this.labGuide.scoring.timeBonus.under15min) {
      score += this.labGuide.scoring.timeBonus.under15min;
    } else if (timeSpent < 30 && this.labGuide.scoring.timeBonus.under30min) {
      score += this.labGuide.scoring.timeBonus.under30min;
    } else if (timeSpent < 45 && this.labGuide.scoring.timeBonus.under45min) {
      score += this.labGuide.scoring.timeBonus.under45min;
    }
    
    // Hint penalty
    hintsUsed.forEach(hintIndex => {
      score -= this.labGuide.scoring.hintPenalty.perHint[hintIndex];
    });
    
    // Create modal
    const modal = document.createElement('div');
    modal.className = 'completion-modal';
    modal.innerHTML = `
      <div class="completion-content">
        <div class="completion-header">
          <h2>${completion.title}</h2>
          <p>${completion.message}</p>
        </div>
        
        <div class="completion-stats">
          <h3>Your Stats:</h3>
          <ul>
            <li>Time: ${timeSpent} minutes</li>
            <li>Hints used: ${hintsUsed}</li>
            <li>Score: ${score} points</li>
          </ul>
        </div>
        
        <div class="completion-learned">
          <h3>What You Learned:</h3>
          <ul>
            ${completion.whatYouLearned.map(item => `<li>${item}</li>`).join('')}
          </ul>
        </div>
        
        <div class="completion-prevention">
          <h3>How to Prevent:</h3>
          <ul>
            ${completion.prevention.map(item => `<li>${item}</li>`).join('')}
          </ul>
        </div>
        
        <div class="completion-next">
          <h3>Next Steps:</h3>
          ${completion.nextSteps.map(step => `
            <div class="next-step">
              <strong>${step.title}</strong>
              <p>${step.description}</p>
              <a href="${step.link}">Start →</a>
            </div>
          `).join('')}
        </div>
        
        <button class="close-completion">Continue Learning</button>
      </div>
      
      <style>
        .completion-modal {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0,0,0,0.8);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 10000;
        }
        
        .completion-content {
          background: white;
          padding: 40px;
          border-radius: 12px;
          max-width: 600px;
          max-height: 80vh;
          overflow-y: auto;
        }
        
        .completion-header {
          text-align: center;
          margin-bottom: 30px;
        }
        
        .completion-header h2 {
          color: #28a745;
          font-size: 32px;
          margin-bottom: 10px;
        }
        
        .completion-stats {
          background: #f8f9fa;
          padding: 20px;
          border-radius: 8px;
          margin: 20px 0;
        }
        
        .next-step {
          border: 1px solid #ddd;
          padding: 15px;
          margin: 10px 0;
          border-radius: 4px;
        }
        
        .next-step a {
          color: #007bff;
          text-decoration: none;
          font-weight: bold;
        }
        
        .close-completion {
          width: 100%;
          padding: 12px;
          background: #007bff;
          color: white;
          border: none;
          border-radius: 4px;
          font-size: 16px;
          cursor: pointer;
          margin-top: 20px;
        }
      </style>
    `;
    
    document.body.appendChild(modal);
    
    // Close button
    modal.querySelector('.close-completion').addEventListener('click', () => {
      modal.remove();
    });
  }
  
  startTimer() {
    // Update timer display every second
    setInterval(() => {
      const elapsed = Math.round((Date.now() - this.state.startTime) / 1000 / 60);
      // Could show timer in panel
    }, 1000);
  }
  
  saveState() {
    localStorage.setItem(
      `lab_state_${this.labGuide.id}`,
      JSON.stringify(this.state)
    );
  }
  
  loadState() {
    const saved = localStorage.getItem(`lab_state_${this.labGuide.id}`);
    if (saved) {
      this.state = { ...this.state, ...JSON.parse(saved) };
    }
  }
}

// Auto-initialize when lab loads
document.addEventListener('DOMContentLoaded', async () => {
  // Fetch lab guide
  const response = await fetch('/api/lab-guide');
  const labGuide = await response.json();
  
  // Initialize gamification
  window.labGamification = new LabGamification(labGuide);
});
```

---

## Component 3: Server-Side API

### routes/gamification.js (Backend)

```javascript
const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

// Load lab guide
const labGuide = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../../lab-guide.json'), 'utf8')
);

// Get lab guide (excluding sensitive info like actual flag)
router.get('/api/lab-guide', (req, res) => {
  // Return guide without revealing the flag
  const safeGuide = {
    ...labGuide,
    validation: {
      ...labGuide.validation,
      flag: undefined // Don't send actual flag to client
    }
  };
  
  res.json(safeGuide);
});

// Validate flag submission
router.post('/api/validate-flag', (req, res) => {
  const { flag } = req.body;
  
  const isCorrect = flag.trim().toLowerCase() === 
                   labGuide.validation.flag.toLowerCase();
  
  res.json({
    correct: isCorrect,
    message: isCorrect ? 
      'Congratulations! Flag accepted!' : 
      'Incorrect flag. Try again.'
  });
});

// Submit feedback
router.post('/api/feedback', (req, res) => {
  const feedback = req.body;
  
  // Save feedback (in production, save to database)
  fs.appendFileSync(
    path.join(__dirname, '../../feedback.json'),
    JSON.stringify(feedback) + '\n'
  );
  
  res.json({ success: true });
});

module.exports = router;
```

---

## Component 4: Vulnerable Application Example

### server.js (Main vulnerable app)

```javascript
const express = require('express');
const session = require('express-session');
const gamificationRouter = require('./routes/gamification');

const app = express();

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: 'vulnerable-secret',
  resave: false,
  saveUnresave: true
}));

// Sample users database (vulnerable!)
const users = {
  1000: {
    id: 1000,
    username: 'admin',
    email: 'admin@example.com',
    role: 'admin',
    bio: 'I am the administrator. FLAG: OWASP{br0k3n_4cc3ss_c0ntr0l_1d0r_2021}'
  },
  1001: {
    id: 1001,
    username: 'testuser',
    email: 'test@example.com',
    role: 'user',
    bio: 'Regular user account'
  }
};

// Login endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Simple auth (for demo purposes)
  if (username === 'testuser' && password === 'testpass123') {
    req.session.userId = 1001;
    res.json({ success: true, userId: 1001 });
  } else {
    res.status(401).json({ success: false });
  }
});

// VULNERABLE ENDPOINT - No authorization check!
app.get('/api/profile', (req, res) => {
  const requestedUserId = parseInt(req.query.userId);
  
  // Only checks if user is authenticated, not authorized!
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  // VULNERABILITY: Doesn't check if req.session.userId === requestedUserId
  const user = users[requestedUserId];
  
  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Gamification routes
app.use(gamificationRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable app running on port ${PORT}`);
  console.log(`Gamification enabled!`);
});
```

---

## Usage Instructions

### For Lab Creators:

1. Copy the template structure
2. Modify `lab-guide.json` with your content
3. Create vulnerable application code
4. Include gamification.js in your frontend
5. Test hints and flag validation

### For Students:

1. Start the lab via Lab Manager
2. Gamification panel appears automatically
3. Read mission and objectives
4. Use hints progressively (with point penalties)
5. Submit flag when found
6. See completion screen with learning summary

---

## Benefits

✅ **Structured Learning**: Clear mission, hints, validation  
✅ **Gamification**: Points, time bonuses, badges  
✅ **Progressive Difficulty**: Hints unlock gradually  
✅ **Learning Validation**: Flag proves exploitation  
✅ **Complete Experience**: Completion screen summarizes learning  
✅ **Reusable**: Template works for all lab types  
✅ **Professional**: Matches TryHackMe/HackTheBox quality  

---

*This template transforms simple vulnerable apps into engaging learning experiences* 🎓✨
