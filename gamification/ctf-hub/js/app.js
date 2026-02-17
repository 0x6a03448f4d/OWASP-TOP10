// CTF Hub - Main Application Logic

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    loadProgress();
    updateDashboard();
    checkBadges();
    updateCertificateButtons();
});

// State management
let appState = {
    userName: 'Security Learner',
    completedChallenges: [],
    startDate: new Date().toISOString(),
    activityLog: [],
    badgesEarned: [],
    quizScores: {}
};

// Initialize application
function initializeApp() {
    // Load state from localStorage
    const saved = localStorage.getItem('owaspCTFHub');
    if (saved) {
        appState = JSON.parse(saved);
    }
    
    // Update UI with current state
    document.getElementById('userName').textContent = `Welcome, ${appState.userName}!`;
    
    // Mark completed challenges
    appState.completedChallenges.forEach(id => {
        const card = document.querySelector(`[data-id="${id}"]`);
        if (card) {
            card.classList.add('completed');
        }
    });
}

// Save state to localStorage
function saveState() {
    try {
        localStorage.setItem('owaspCTFHub', JSON.stringify(appState));
    } catch (e) {
        if (e.name === 'QuotaExceededError') {
            alert('Storage quota exceeded. Please export your data and reset to continue.');
        } else {
            console.error('Failed to save progress:', e);
            alert('Failed to save progress. Your browser may have storage disabled.');
        }
    }
}

// Load progress data
function loadProgress() {
    const total = appState.completedChallenges.length;
    const percentage = Math.round((total / 40) * 100);
    
    document.getElementById('totalCompleted').textContent = total;
    document.getElementById('totalBadges').textContent = appState.badgesEarned.length;
    document.getElementById('completionPercent').textContent = `${percentage}%`;
    
    renderActivityLog();
    renderCharts();
}

// Update dashboard
function updateDashboard() {
    loadProgress();
}

// Render activity log
function renderActivityLog() {
    const activityList = document.getElementById('activityList');
    
    if (appState.activityLog.length === 0) {
        activityList.innerHTML = '<p class="no-data">No activity yet. Start a challenge to begin!</p>';
        return;
    }
    
    activityList.innerHTML = appState.activityLog
        .slice(-10)
        .reverse()
        .map(activity => `
            <div class="activity-item">
                <span class="activity-icon">${activity.icon}</span>
                <span class="activity-text">${activity.text}</span>
                <span class="activity-time">${formatTime(activity.timestamp)}</span>
            </div>
        `)
        .join('');
}

// Render progress charts
function renderCharts() {
    renderCategoryChart();
    renderTimelineChart();
}

// Category progress chart
function renderCategoryChart() {
    const ctx = document.getElementById('categoryChart');
    if (!ctx) return;
    
    const categories = {
        web: { total: 10, completed: 0 },
        api: { total: 10, completed: 0 },
        llm: { total: 10, completed: 0 },
        mobile: { total: 10, completed: 0 }
    };
    
    // Count completed per category
    appState.completedChallenges.forEach(id => {
        const category = id.split('-')[0];
        if (categories[category]) {
            categories[category].completed++;
        }
    });
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Web', 'API', 'LLM', 'Mobile'],
            datasets: [{
                label: 'Completed',
                data: [
                    categories.web.completed,
                    categories.api.completed,
                    categories.llm.completed,
                    categories.mobile.completed
                ],
                backgroundColor: '#d9534f'
            }, {
                label: 'Remaining',
                data: [
                    categories.web.total - categories.web.completed,
                    categories.api.total - categories.api.completed,
                    categories.llm.total - categories.llm.completed,
                    categories.mobile.total - categories.mobile.completed
                ],
                backgroundColor: '#e0e0e0'
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { stacked: true },
                y: { stacked: true, max: 10 }
            }
        }
    });
}

// Timeline chart
function renderTimelineChart() {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;
    
    // Aggregate completions by date
    const completionsByDate = {};
    let total = 0;
    
    appState.activityLog
        .filter(a => a.type === 'complete')
        .forEach(activity => {
            const date = new Date(activity.timestamp).toLocaleDateString();
            total++;
            completionsByDate[date] = total;
        });
    
    const labels = Object.keys(completionsByDate);
    const data = Object.values(completionsByDate);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels.length ? labels : ['Start'],
            datasets: [{
                label: 'Total Completed',
                data: data.length ? data : [0],
                borderColor: '#d9534f',
                backgroundColor: 'rgba(217, 83, 79, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

// Launch lab
function launchLab(challengeId) {
    const labPaths = {
        'web-01': '../OWASP-Web/01-Broken-Access-Control/lab/',
        'web-02': '../OWASP-Web/02-Cryptographic-Failures/lab/',
        'web-03': '../OWASP-Web/03-Injection/lab/',
        'web-04': '../OWASP-Web/04-Insecure-Design/lab/',
        'web-05': '../OWASP-Web/05-Security-Misconfiguration/lab/',
        'web-06': '../OWASP-Web/06-Vulnerable-Outdated-Components/lab/',
        'web-07': '../OWASP-Web/07-Identification-Authentication-Failures/lab/',
        'web-08': '../OWASP-Web/08-Software-Data-Integrity-Failures/lab/',
        'web-09': '../OWASP-Web/09-Security-Logging-Monitoring-Failures/lab/',
        'web-10': '../OWASP-Web/10-Server-Side-Request-Forgery/lab/'
    };
    
    const path = labPaths[challengeId];
    if (path) {
        logActivity('🚀', `Launched ${challengeId} lab`, 'launch');
        saveState();
        alert(`Lab instructions:\n\n1. Navigate to: ${path}\n2. Run: docker-compose up\n3. Follow lab instructions\n4. Return here to mark complete!`);
    } else {
        alert('This lab is coming soon! Check back later.');
    }
}

// View documentation
function viewDocs(challengeId) {
    const docPaths = {
        'web-01': '../OWASP-Web/01-Broken-Access-Control/overview.md',
        'web-02': '../OWASP-Web/02-Cryptographic-Failures/overview.md',
        'web-03': '../OWASP-Web/03-Injection/overview.md',
        'web-04': '../OWASP-Web/04-Insecure-Design/overview.md',
        'web-05': '../OWASP-Web/05-Security-Misconfiguration/overview.md',
        'web-06': '../OWASP-Web/06-Vulnerable-Outdated-Components/overview.md',
        'web-07': '../OWASP-Web/07-Identification-Authentication-Failures/overview.md',
        'web-08': '../OWASP-Web/08-Software-Data-Integrity-Failures/overview.md',
        'web-09': '../OWASP-Web/09-Security-Logging-Monitoring-Failures/overview.md',
        'web-10': '../OWASP-Web/10-Server-Side-Request-Forgery/overview.md'
    };
    
    const path = docPaths[challengeId];
    if (path) {
        window.open(path, '_blank');
    }
}

// Mark challenge complete
function markComplete(challengeId) {
    if (appState.completedChallenges.includes(challengeId)) {
        alert('You have already completed this challenge!');
        return;
    }
    
    const confirmed = confirm('Have you completed this challenge?\n\nClick OK to mark as complete.');
    if (!confirmed) return;
    
    appState.completedChallenges.push(challengeId);
    
    const card = document.querySelector(`[data-id="${challengeId}"]`);
    if (card) {
        card.classList.add('completed');
    }
    
    logActivity('✅', `Completed ${challengeId}`, 'complete');
    
    saveState();
    updateDashboard();
    checkBadges();
    updateCertificateButtons();
    
    alert('🎉 Congratulations! Challenge marked as complete!');
}

// Log activity
function logActivity(icon, text, type) {
    appState.activityLog.push({
        icon: icon,
        text: text,
        type: type,
        timestamp: new Date().toISOString()
    });
    
    // Keep only last 100 activities
    if (appState.activityLog.length > 100) {
        appState.activityLog = appState.activityLog.slice(-100);
    }
}

// Filter challenges by category
function filterChallenges(category) {
    const categories = document.querySelectorAll('.challenge-category');
    const buttons = document.querySelectorAll('.filter-btn');
    
    buttons.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    categories.forEach(cat => {
        if (category === 'all') {
            cat.style.display = 'block';
        } else {
            cat.style.display = cat.dataset.category === category ? 'block' : 'none';
        }
    });
}

// Edit user name
function editName() {
    const newName = prompt('Enter your name:', appState.userName);
    if (newName && newName.trim()) {
        appState.userName = newName.trim();
        document.getElementById('userName').textContent = `Welcome, ${appState.userName}!`;
        saveState();
    }
}

// Show settings modal
function showSettings() {
    document.getElementById('settingsModal').style.display = 'block';
}

// Close settings modal
function closeSettings() {
    document.getElementById('settingsModal').style.display = 'none';
}

// Export progress
function exportProgress() {
    const dataStr = JSON.stringify(appState, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `owasp-ctf-progress-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    
    alert('Progress exported successfully!');
}

// Import progress
function importProgress() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'application/json';
    
    input.onchange = e => {
        const file = e.target.files[0];
        const reader = new FileReader();
        
        reader.onload = event => {
            try {
                const imported = JSON.parse(event.target.result);
                if (confirm('This will replace your current progress. Continue?')) {
                    appState = imported;
                    saveState();
                    location.reload();
                }
            } catch (err) {
                alert('Error importing file. Please check the file format.');
            }
        };
        
        reader.readAsText(file);
    };
    
    input.click();
}

// Reset all progress
function resetProgress() {
    const confirmed = confirm('⚠️ WARNING: This will delete all your progress!\n\nAre you absolutely sure?');
    if (!confirmed) return;
    
    const doubleConfirm = confirm('This action cannot be undone. Proceed?');
    if (!doubleConfirm) return;
    
    localStorage.removeItem('owaspCTFHub');
    location.reload();
}

// Update certificate buttons
function updateCertificateButtons() {
    const categories = {
        web: { total: 10, completed: 0 },
        api: { total: 10, completed: 0 },
        llm: { total: 10, completed: 0 },
        mobile: { total: 10, completed: 0 }
    };
    
    appState.completedChallenges.forEach(id => {
        const category = id.split('-')[0];
        if (categories[category]) {
            categories[category].completed++;
        }
    });
    
    // Enable certificate buttons for completed categories
    Object.keys(categories).forEach(cat => {
        const btn = document.getElementById(`cert-${cat}`);
        if (btn && categories[cat].completed === categories[cat].total) {
            btn.disabled = false;
        }
    });
    
    // Master certificate (all 40 complete)
    const masterBtn = document.getElementById('cert-master');
    if (masterBtn && appState.completedChallenges.length === 40) {
        masterBtn.disabled = false;
    }
}

// Format timestamp
function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
}

// Smooth scroll for navigation
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});
