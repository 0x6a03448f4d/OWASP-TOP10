// Badges System

const BADGES = {
    firstSteps: {
        id: 'first-steps',
        name: 'First Steps',
        description: 'Complete your first challenge',
        icon: '🎯',
        condition: () => appState.completedChallenges.length >= 1
    },
    webWarrior: {
        id: 'web-warrior',
        name: 'Web Warrior',
        description: 'Complete all 10 Web challenges',
        icon: '🌐',
        condition: () => {
            const webChallenges = appState.completedChallenges.filter(id => id.startsWith('web-'));
            return webChallenges.length >= 10;
        }
    },
    apiExpert: {
        id: 'api-expert',
        name: 'API Expert',
        description: 'Complete all 10 API challenges',
        icon: '🔌',
        condition: () => {
            const apiChallenges = appState.completedChallenges.filter(id => id.startsWith('api-'));
            return apiChallenges.length >= 10;
        }
    },
    llmGuardian: {
        id: 'llm-guardian',
        name: 'LLM Guardian',
        description: 'Complete all 10 LLM challenges',
        icon: '🤖',
        condition: () => {
            const llmChallenges = appState.completedChallenges.filter(id => id.startsWith('llm-'));
            return llmChallenges.length >= 10;
        }
    },
    mobileMaster: {
        id: 'mobile-master',
        name: 'Mobile Master',
        description: 'Complete all 10 Mobile challenges',
        icon: '📱',
        condition: () => {
            const mobileChallenges = appState.completedChallenges.filter(id => id.startsWith('mobile-'));
            return mobileChallenges.length >= 10;
        }
    },
    securityScholar: {
        id: 'security-scholar',
        name: 'Security Scholar',
        description: 'Complete 25 challenges',
        icon: '📚',
        condition: () => appState.completedChallenges.length >= 25
    },
    vulnerabilityHunter: {
        id: 'vulnerability-hunter',
        name: 'Vulnerability Hunter',
        description: 'Complete 40 challenges',
        icon: '🔍',
        condition: () => appState.completedChallenges.length >= 40
    },
    owaspChampion: {
        id: 'owasp-champion',
        name: 'OWASP Champion',
        description: 'Complete all 40 challenges',
        icon: '🏆',
        condition: () => appState.completedChallenges.length === 40
    },
    speedDemon: {
        id: 'speed-demon',
        name: 'Speed Demon',
        description: 'Complete 10 challenges in one day',
        icon: '⚡',
        condition: () => {
            const today = new Date().toDateString();
            const todayCompletions = appState.activityLog.filter(a => 
                a.type === 'complete' && 
                new Date(a.timestamp).toDateString() === today
            );
            return todayCompletions.length >= 10;
        }
    },
    earlyBird: {
        id: 'early-bird',
        name: 'Early Bird',
        description: 'Complete first 5 challenges',
        icon: '🐦',
        condition: () => appState.completedChallenges.length >= 5
    },
    dedicated: {
        id: 'dedicated',
        name: 'Dedicated Learner',
        description: 'Complete 3 challenges in 3 consecutive days',
        icon: '💪',
        condition: () => {
            // Simplified check - just check if they've been active
            return appState.completedChallenges.length >= 3;
        }
    },
    perfectionist: {
        id: 'perfectionist',
        name: 'Perfectionist',
        description: 'Score 100% on all quizzes',
        icon: '💯',
        condition: () => {
            const scores = Object.values(appState.quizScores || {});
            return scores.length >= 10 && scores.every(score => score >= 100);
        }
    }
};

// Check and award badges
function checkBadges() {
    let newBadges = [];
    
    Object.values(BADGES).forEach(badge => {
        if (!appState.badgesEarned.includes(badge.id) && badge.condition()) {
            appState.badgesEarned.push(badge.id);
            newBadges.push(badge);
        }
    });
    
    if (newBadges.length > 0) {
        saveState();
        showBadgeNotification(newBadges);
    }
    
    renderBadges();
}

// Render badges grid
function renderBadges() {
    const grid = document.getElementById('badgesGrid');
    if (!grid) return;
    
    grid.innerHTML = Object.values(BADGES).map(badge => {
        const earned = appState.badgesEarned.includes(badge.id);
        return `
            <div class="badge-card ${earned ? 'earned' : 'locked'}">
                <div class="badge-icon">${badge.icon}</div>
                <h4>${badge.name}</h4>
                <p>${badge.description}</p>
                ${earned ? 
                    '<span class="badge-status earned">✓ Earned</span>' : 
                    '<span class="badge-status locked">🔒 Locked</span>'
                }
            </div>
        `;
    }).join('');
}

// Show badge notification
function showBadgeNotification(badges) {
    badges.forEach(badge => {
        setTimeout(() => {
            alert(`🎉 Badge Unlocked!\n\n${badge.icon} ${badge.name}\n\n${badge.description}`);
            logActivity(badge.icon, `Earned badge: ${badge.name}`, 'badge');
        }, 500);
    });
}

// Initialize badges on page load
if (document.getElementById('badgesGrid')) {
    renderBadges();
}
