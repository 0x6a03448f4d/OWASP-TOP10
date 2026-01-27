// Quiz Application State
let quizMode = null; // 'quick', 'category', 'comprehensive', 'custom'
let selectedCategories = [];
let currentQuestions = [];
let currentQuestion = 0;
let userAnswers = [];
let score = 0;
let startTime = null;
let timerInterval = null;

// LocalStorage key for progress tracking
const STORAGE_KEY = 'owaspQuizProgress';

// Initialize progress tracking
function initProgress() {
    const progress = getProgress();
    if (!progress.history) progress.history = [];
    if (!progress.stats) progress.stats = { web: 0, api: 0, mobile: 0, llm: 0 };
    if (!progress.totalQuizzes) progress.totalQuizzes = 0;
    if (!progress.certificates) progress.certificates = [];
    return progress;
}

function getProgress() {
    try {
        return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {};
    } catch {
        return {};
    }
}

function saveProgress(data) {
    try {
        const current = getProgress();
        localStorage.setItem(STORAGE_KEY, JSON.stringify({...current, ...data}));
    } catch (e) {
        console.error('Failed to save progress:', e);
    }
}

// Mode Selection
function selectMode(mode) {
    quizMode = mode;
    document.getElementById('mode-selection').style.display = 'none';
    
    if (mode === 'comprehensive') {
        startComprehensiveExam();
    } else if (mode === 'custom') {
        document.getElementById('custom-selection').style.display = 'block';
    } else {
        // Show category selection
        document.getElementById('category-selection').style.display = 'block';
        updateCategoryQuestionCounts();
        
        const description = mode === 'quick' 
            ? '5 random questions to test your knowledge quickly'
            : '15 comprehensive questions to master the category';
        document.getElementById('mode-description').textContent = description;
    }
}

function updateCategoryQuestionCounts() {
    const count = quizMode === 'quick' ? '5 Questions' : '15 Questions';
    document.getElementById('web-count').textContent = count;
    document.getElementById('api-count').textContent = count;
    document.getElementById('mobile-count').textContent = count;
    document.getElementById('llm-count').textContent = count;
}

function backToModes() {
    document.getElementById('category-selection').style.display = 'none';
    document.getElementById('custom-selection').style.display = 'none';
    document.getElementById('mode-selection').style.display = 'block';
    selectedCategories = [];
    document.querySelectorAll('.category-checkbox input').forEach(cb => {
        cb.checked = false;
        cb.parentElement.classList.remove('selected');
    });
}

function toggleCategory(category) {
    const checkbox = document.getElementById('check-' + category);
    checkbox.checked = !checkbox.checked;
    checkbox.parentElement.classList.toggle('selected', checkbox.checked);
}

function startCustomQuiz() {
    selectedCategories = [];
    document.querySelectorAll('.category-checkbox input:checked').forEach(cb => {
        const category = cb.id.replace('check-', '');
        selectedCategories.push(category);
    });
    
    if (selectedCategories.length === 0) {
        alert('Please select at least one category');
        return;
    }
    
    currentQuestions = [];
    selectedCategories.forEach(cat => {
        const questions = [...quizQuestions[cat]];
        shuffleArray(questions);
        currentQuestions.push(...questions.slice(0, 10)); // 10 per category
    });
    
    shuffleArray(currentQuestions);
    startQuizExecution();
}

function startComprehensiveExam() {
    currentQuestions = [];
    ['web', 'api', 'mobile', 'llm'].forEach(cat => {
        const questions = [...quizQuestions[cat]];
        shuffleArray(questions);
        currentQuestions.push(...questions.slice(0, 10)); // 10 from each = 40 total
    });
    
    shuffleArray(currentQuestions);
    startQuizExecution();
}

function startQuiz(category) {
    selectedCategories = [category];
    const questions = [...quizQuestions[category]];
    shuffleArray(questions);
    
    if (quizMode === 'quick') {
        currentQuestions = questions.slice(0, 5);
    } else {
        currentQuestions = questions.slice(0, 15);
    }
    
    startQuizExecution();
}

function startQuizExecution() {
    document.getElementById('category-selection').style.display = 'none';
    document.getElementById('custom-selection').style.display = 'none';
    document.getElementById('quiz-area').classList.add('active');
    
    currentQuestion = 0;
    userAnswers = [];
    score = 0;
    startTime = Date.now();
    
    startTimer();
    loadQuestion();
}

function startTimer() {
    const timerElement = document.getElementById('timer');
    timerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        timerElement.innerHTML = `<i class="fas fa-clock"></i> ${minutes}:${seconds.toString().padStart(2, '0')}`;
    }, 1000);
}

function stopTimer() {
    if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
    }
}

function loadQuestion() {
    const question = currentQuestions[currentQuestion];
    const container = document.getElementById('question-container');
    
    let typeLabel = '';
    let questionHTML = '';
    
    if (question.type === 'boolean') {
        typeLabel = '<span class="question-type"><i class="fas fa-check-circle"></i> True/False</span>';
    } else if (question.type === 'scenario') {
        typeLabel = '<span class="question-type"><i class="fas fa-book"></i> Scenario-Based</span>';
    } else {
        typeLabel = '<span class="question-type"><i class="fas fa-list"></i> Multiple Choice</span>';
    }
    
    if (question.scenario) {
        questionHTML = `
            <div class="scenario-text">
                <strong>📖 Scenario:</strong><br>
                ${question.scenario}
            </div>
        `;
    }
    
    container.innerHTML = `
        <div class="question-card">
            ${typeLabel}
            <div class="question-text">
                Question ${currentQuestion + 1} of ${currentQuestions.length}
            </div>
            ${questionHTML}
            <div class="question-text" style="margin-top: ${question.scenario ? '15px' : '0'};">
                ${question.question}
            </div>
            ${question.options.map((option, index) => `
                <div class="answer-option" onclick="selectAnswer(${index})">
                    <input type="radio" name="answer" value="${index}" style="margin-right: 10px;">
                    ${option}
                </div>
            `).join('')}
            <div class="explanation" id="explanation-${currentQuestion}">
                <h4><i class="fas fa-lightbulb"></i> Explanation:</h4>
                <p>${question.explanation}</p>
            </div>
        </div>
    `;

    // Update progress
    const progress = ((currentQuestion + 1) / currentQuestions.length) * 100;
    document.getElementById('progress-fill').style.width = progress + '%';
    document.getElementById('question-counter').textContent = 
        `Question ${currentQuestion + 1} of ${currentQuestions.length}`;

    // Update buttons
    document.getElementById('prev-btn').disabled = currentQuestion === 0;
    const nextBtn = document.getElementById('next-btn');
    
    if (currentQuestion === currentQuestions.length - 1) {
        nextBtn.innerHTML = 'Finish <i class="fas fa-flag-checkered"></i>';
    } else {
        nextBtn.innerHTML = 'Next <i class="fas fa-arrow-right"></i>';
    }

    // Restore previous answer if exists
    if (userAnswers[currentQuestion] !== undefined) {
        selectAnswer(userAnswers[currentQuestion], false);
    }
}

function selectAnswer(index, store = true) {
    if (store) {
        userAnswers[currentQuestion] = index;
    }
    
    document.querySelectorAll('.answer-option').forEach((option, i) => {
        option.classList.toggle('selected', i === index);
        if (i === index) {
            option.querySelector('input').checked = true;
        }
    });
}

function nextQuestion() {
    const question = currentQuestions[currentQuestion];
    
    // Show explanation if answer was selected
    if (userAnswers[currentQuestion] !== undefined) {
        const explanation = document.getElementById(`explanation-${currentQuestion}`);
        if (explanation && !explanation.classList.contains('show')) {
            explanation.classList.add('show');
            
            // Highlight correct/incorrect
            document.querySelectorAll('.answer-option').forEach((option, i) => {
                if (i === question.correct) {
                    option.classList.add('correct');
                }
                if (i === userAnswers[currentQuestion] && i !== question.correct) {
                    option.classList.add('incorrect');
                }
            });
            
            // Change button text temporarily
            const nextBtn = document.getElementById('next-btn');
            const originalText = nextBtn.innerHTML;
            nextBtn.innerHTML = '<i class="fas fa-arrow-right"></i> Continue';
            
            setTimeout(() => {
                nextBtn.innerHTML = originalText;
            }, 500);
            
            return; // Don't advance yet
        }
    }
    
    if (currentQuestion === currentQuestions.length - 1) {
        showResults();
    } else {
        currentQuestion++;
        loadQuestion();
    }
}

function previousQuestion() {
    if (currentQuestion > 0) {
        currentQuestion--;
        loadQuestion();
    }
}

function showResults() {
    stopTimer();
    const totalTime = Math.floor((Date.now() - startTime) / 1000);
    
    // Calculate score
    score = 0;
    userAnswers.forEach((answer, index) => {
        if (answer === currentQuestions[index].correct) {
            score++;
        }
    });

    const totalQuestions = currentQuestions.length;
    const percentage = (score / totalQuestions) * 100;

    document.getElementById('quiz-area').classList.remove('active');
    document.getElementById('results-area').classList.add('active');
    
    document.getElementById('final-score').textContent = `${score}/${totalQuestions}`;
    
    // Update icon and message based on score
    const icon = document.getElementById('result-icon');
    let message = '';
    
    if (percentage >= 90) {
        message = '🏆 Outstanding! You are a cybersecurity expert!';
        icon.className = 'fas fa-trophy';
    } else if (percentage >= 80) {
        message = '🎯 Excellent! You have strong security knowledge!';
        icon.className = 'fas fa-medal';
    } else if (percentage >= 70) {
        message = '✅ Good job! You\'re on the right track!';
        icon.className = 'fas fa-check-circle';
    } else if (percentage >= 60) {
        message = '📚 Not bad! Keep studying to improve!';
        icon.className = 'fas fa-book-reader';
    } else {
        message = '💪 Keep learning! Review the materials and try again!';
        icon.className = 'fas fa-redo';
    }
    
    document.getElementById('score-message').textContent = message;

    // Show certificate if score >= 80%
    const certificateContainer = document.getElementById('certificate-container');
    if (percentage >= 80) {
        const examType = quizMode === 'comprehensive' ? 'Comprehensive Security Exam' :
                        quizMode === 'custom' ? 'Custom Security Exam' :
                        quizMode === 'category' ? selectedCategories[0].toUpperCase() + ' Security Expert' :
                        selectedCategories[0].toUpperCase() + ' Security Quiz';
        
        certificateContainer.innerHTML = `
            <div class="certificate">
                <h3>🎓 Certificate of Achievement</h3>
                <div class="badge">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <p style="color: #a0a0a0; font-size: 1.1rem; margin: 15px 0;">
                    Congratulations on achieving ${percentage.toFixed(1)}% in
                </p>
                <h4 style="color: var(--matrix-green); font-size: 1.3rem; margin: 10px 0;">
                    ${examType}
                </h4>
                <p style="color: #777; margin-top: 20px; font-size: 0.9rem;">
                    Issued: ${new Date().toLocaleDateString()}
                </p>
            </div>
        `;
        
        // Save certificate
        saveCertificate(examType, percentage, totalQuestions);
    } else {
        certificateContainer.innerHTML = '';
    }

    // Display stats
    const minutes = Math.floor(totalTime / 60);
    const seconds = totalTime % 60;
    const timeStr = `${minutes}:${seconds.toString().padStart(2, '0')}`;
    
    document.getElementById('stats-container').innerHTML = `
        <div class="stat-card">
            <h4>Score</h4>
            <div class="value">${percentage.toFixed(1)}%</div>
        </div>
        <div class="stat-card">
            <h4>Correct</h4>
            <div class="value" style="color: var(--matrix-green);">${score}</div>
        </div>
        <div class="stat-card">
            <h4>Incorrect</h4>
            <div class="value" style="color: #ff0040;">${totalQuestions - score}</div>
        </div>
        <div class="stat-card">
            <h4>Time</h4>
            <div class="value">${timeStr}</div>
        </div>
    `;

    // Save to history
    saveToHistory(percentage, totalQuestions, timeStr);
}

function saveCertificate(examType, percentage, totalQuestions) {
    const progress = getProgress();
    if (!progress.certificates) progress.certificates = [];
    
    progress.certificates.push({
        type: examType,
        score: percentage,
        total: totalQuestions,
        date: new Date().toISOString()
    });
    
    saveProgress(progress);
}

function saveToHistory(percentage, totalQuestions, time) {
    const progress = getProgress();
    if (!progress.history) progress.history = [];
    if (!progress.stats) progress.stats = { web: 0, api: 0, mobile: 0, llm: 0 };
    
    progress.history.push({
        mode: quizMode,
        categories: selectedCategories,
        score: score,
        total: totalQuestions,
        percentage: percentage,
        time: time,
        date: new Date().toISOString()
    });
    
    progress.totalQuizzes = (progress.totalQuizzes || 0) + 1;
    
    // Update category stats
    selectedCategories.forEach(cat => {
        progress.stats[cat] = (progress.stats[cat] || 0) + 1;
    });
    
    saveProgress(progress);
}

function reviewAnswers() {
    document.getElementById('results-area').classList.remove('active');
    document.getElementById('review-area').classList.add('active');
    
    const reviewContainer = document.getElementById('review-container');
    let reviewHTML = '';
    
    currentQuestions.forEach((question, index) => {
        const userAnswer = userAnswers[index];
        const isCorrect = userAnswer === question.correct;
        
        reviewHTML += `
            <div class="review-item ${!isCorrect ? 'wrong' : ''}">
                <h4>
                    <i class="fas fa-${isCorrect ? 'check-circle' : 'times-circle'}" 
                       style="color: ${isCorrect ? 'var(--matrix-green)' : '#ff0040'};"></i>
                    Question ${index + 1}: ${question.question}
                </h4>
                ${question.scenario ? `<p style="color: #888; font-style: italic; margin: 10px 0;">${question.scenario}</p>` : ''}
                
                ${userAnswer !== undefined ? `
                    <div class="review-answer user">
                        <strong>Your Answer:</strong> ${question.options[userAnswer]}
                    </div>
                ` : `
                    <div class="review-answer user">
                        <strong>Your Answer:</strong> <em>Not answered</em>
                    </div>
                `}
                
                ${!isCorrect ? `
                    <div class="review-answer correct-ans">
                        <strong>Correct Answer:</strong> ${question.options[question.correct]}
                    </div>
                ` : ''}
                
                <div style="margin-top: 15px; padding: 15px; background: rgba(0, 255, 65, 0.05); border-radius: 6px; border-left: 3px solid var(--matrix-green);">
                    <strong style="color: var(--matrix-green);"><i class="fas fa-lightbulb"></i> Explanation:</strong>
                    <p style="color: #d0d0d0; margin-top: 8px;">${question.explanation}</p>
                </div>
            </div>
        `;
    });
    
    reviewContainer.innerHTML = reviewHTML;
}

function backToResults() {
    document.getElementById('review-area').classList.remove('active');
    document.getElementById('results-area').classList.add('active');
}

function restartQuiz() {
    stopTimer();
    document.getElementById('results-area').classList.remove('active');
    document.getElementById('review-area').classList.remove('active');
    document.getElementById('mode-selection').style.display = 'block';
    
    // Reset state
    quizMode = null;
    selectedCategories = [];
    currentQuestions = [];
    currentQuestion = 0;
    userAnswers = [];
    score = 0;
}

function showProgress() {
    const progress = getProgress();
    const history = progress.history || [];
    const certificates = progress.certificates || [];
    const stats = progress.stats || {};
    
    let progressHTML = `
        <div style="background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%); padding: 30px; border-radius: 12px; border: 1px solid rgba(0, 255, 65, 0.3);">
            <h2 style="color: var(--matrix-green); margin-bottom: 20px;">
                <i class="fas fa-chart-line"></i> Your Progress
            </h2>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h4>Total Quizzes</h4>
                    <div class="value">${progress.totalQuizzes || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>Certificates</h4>
                    <div class="value">${certificates.length}</div>
                </div>
                <div class="stat-card">
                    <h4>Web Quizzes</h4>
                    <div class="value">${stats.web || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>API Quizzes</h4>
                    <div class="value">${stats.api || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>Mobile Quizzes</h4>
                    <div class="value">${stats.mobile || 0}</div>
                </div>
                <div class="stat-card">
                    <h4>LLM Quizzes</h4>
                    <div class="value">${stats.llm || 0}</div>
                </div>
            </div>
    `;
    
    if (certificates.length > 0) {
        progressHTML += `
            <h3 style="color: var(--matrix-green); margin: 30px 0 15px;">
                <i class="fas fa-certificate"></i> Your Certificates
            </h3>
        `;
        certificates.slice(-5).reverse().forEach(cert => {
            progressHTML += `
                <div class="review-item">
                    <h4><i class="fas fa-award"></i> ${cert.type}</h4>
                    <p style="color: #a0a0a0;">Score: ${cert.score.toFixed(1)}% | ${new Date(cert.date).toLocaleDateString()}</p>
                </div>
            `;
        });
    }
    
    if (history.length > 0) {
        progressHTML += `
            <h3 style="color: var(--matrix-green); margin: 30px 0 15px;">
                <i class="fas fa-history"></i> Recent History
            </h3>
        `;
        history.slice(-10).reverse().forEach(item => {
            const passed = item.percentage >= 70;
            progressHTML += `
                <div class="review-item ${!passed ? 'wrong' : ''}">
                    <h4>
                        <i class="fas fa-${passed ? 'check-circle' : 'times-circle'}" 
                           style="color: ${passed ? 'var(--matrix-green)' : '#ff0040'};"></i>
                        ${item.mode.charAt(0).toUpperCase() + item.mode.slice(1)} - ${item.categories.join(', ').toUpperCase()}
                    </h4>
                    <p style="color: #a0a0a0;">
                        Score: ${item.score}/${item.total} (${item.percentage.toFixed(1)}%) | 
                        Time: ${item.time} | 
                        ${new Date(item.date).toLocaleDateString()}
                    </p>
                </div>
            `;
        });
    }
    
    progressHTML += `
            <div style="text-align: center; margin-top: 30px;">
                <button class="btn btn-secondary" onclick="closeProgress()">
                    <i class="fas fa-times"></i> Close
                </button>
                <button class="btn btn-primary" onclick="clearProgress()" style="margin-left: 15px;">
                    <i class="fas fa-trash"></i> Clear History
                </button>
            </div>
        </div>
    `;
    
    const modal = document.createElement('div');
    modal.id = 'progress-modal';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        z-index: 9999;
        overflow-y: auto;
        padding: 40px 20px;
    `;
    modal.innerHTML = `<div style="max-width: 1000px; margin: 0 auto;">${progressHTML}</div>`;
    document.body.appendChild(modal);
}

function closeProgress() {
    const modal = document.getElementById('progress-modal');
    if (modal) modal.remove();
}

function clearProgress() {
    if (confirm('Are you sure you want to clear all progress and certificates? This cannot be undone.')) {
        localStorage.removeItem(STORAGE_KEY);
        closeProgress();
        alert('Progress cleared successfully!');
    }
}

// Utility function to shuffle array
function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initProgress();
});
