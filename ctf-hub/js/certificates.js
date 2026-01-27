// Certificate Generation System

// Generate certificate
function generateCertificate(category) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({
        orientation: 'landscape',
        unit: 'mm',
        format: 'a4'
    });
    
    const date = new Date().toLocaleDateString();
    const certId = generateCertId();
    
    // Certificate background
    doc.setFillColor(255, 255, 255);
    doc.rect(0, 0, 297, 210, 'F');
    
    // Border
    doc.setDrawColor(217, 83, 79);
    doc.setLineWidth(3);
    doc.rect(10, 10, 277, 190);
    
    doc.setLineWidth(1);
    doc.rect(15, 15, 267, 180);
    
    // OWASP Logo text
    doc.setFontSize(40);
    doc.setTextColor(217, 83, 79);
    doc.setFont('helvetica', 'bold');
    doc.text('🛡️ OWASP', 148.5, 40, { align: 'center' });
    
    // Certificate title
    doc.setFontSize(28);
    doc.setTextColor(44, 62, 80);
    doc.text('Certificate of Completion', 148.5, 55, { align: 'center' });
    
    // Divider
    doc.setDrawColor(217, 83, 79);
    doc.setLineWidth(0.5);
    doc.line(70, 62, 227, 62);
    
    // Awarded to
    doc.setFontSize(16);
    doc.setTextColor(100, 100, 100);
    doc.text('This is to certify that', 148.5, 75, { align: 'center' });
    
    // User name
    doc.setFontSize(32);
    doc.setTextColor(217, 83, 79);
    doc.setFont('helvetica', 'bold');
    doc.text(appState.userName, 148.5, 90, { align: 'center' });
    
    // Achievement line
    doc.setFontSize(16);
    doc.setTextColor(100, 100, 100);
    doc.setFont('helvetica', 'normal');
    doc.text('has successfully completed', 148.5, 105, { align: 'center' });
    
    // Category name
    let categoryName = '';
    let categoryIcon = '';
    
    switch(category) {
        case 'web':
            categoryName = 'OWASP Web Application Security Top 10';
            categoryIcon = '🌐';
            break;
        case 'api':
            categoryName = 'OWASP API Security Top 10';
            categoryIcon = '🔌';
            break;
        case 'llm':
            categoryName = 'OWASP LLM Security Top 10';
            categoryIcon = '🤖';
            break;
        case 'mobile':
            categoryName = 'OWASP Mobile Security Top 10';
            categoryIcon = '📱';
            break;
        case 'master':
            categoryName = 'OWASP Top 10 - Master Certificate';
            categoryIcon = '🏆';
            break;
    }
    
    doc.setFontSize(24);
    doc.setTextColor(217, 83, 79);
    doc.setFont('helvetica', 'bold');
    doc.text(`${categoryIcon} ${categoryName}`, 148.5, 120, { align: 'center' });
    
    // Completion details
    doc.setFontSize(14);
    doc.setTextColor(100, 100, 100);
    doc.setFont('helvetica', 'normal');
    
    const completedCount = category === 'master' ? 40 : 10;
    doc.text(`Successfully completing ${completedCount} challenges`, 148.5, 135, { align: 'center' });
    doc.text('demonstrating comprehensive knowledge of security vulnerabilities', 148.5, 143, { align: 'center' });
    
    // Date and Certificate ID
    doc.setFontSize(12);
    doc.setTextColor(80, 80, 80);
    doc.text(`Date: ${date}`, 50, 165);
    doc.text(`Certificate ID: ${certId}`, 50, 172);
    
    // Signature line
    doc.setDrawColor(150, 150, 150);
    doc.line(200, 170, 260, 170);
    doc.setFontSize(10);
    doc.text('OWASP Educational Repository', 230, 176, { align: 'center' });
    
    // Footer
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text('This certificate was generated from the OWASP Top 10 Educational Repository', 148.5, 190, { align: 'center' });
    doc.text('Verify at: github.com/0x6a03448f4d/OWASP-TOP10', 148.5, 195, { align: 'center' });
    
    // Save PDF
    // Sanitize username for filename - only allow alphanumeric, spaces, hyphens, underscores
    const sanitizedName = appState.userName.replace(/[^a-zA-Z0-9\s\-_]/g, '').replace(/\s+/g, '-').substring(0, 50);
    const fileName = `OWASP-${category.toUpperCase()}-Certificate-${sanitizedName}-${date.replace(/\//g, '-')}.pdf`;
    doc.save(fileName);
    
    // Log activity
    logActivity('📜', `Generated ${category} certificate`, 'certificate');
    saveState();
    
    alert(`✅ Certificate generated successfully!\n\nSaved as: ${fileName}`);
}

// Generate unique certificate ID
function generateCertId() {
    const timestamp = Date.now().toString(36);
    const randomStr = Math.random().toString(36).substring(2, 8);
    return `OWASP-${timestamp}-${randomStr}`.toUpperCase();
}

// Update certificate buttons based on completion
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
        if (btn) {
            if (categories[cat].completed === categories[cat].total) {
                btn.disabled = false;
                btn.textContent = '📥 Download Certificate';
            } else {
                btn.disabled = true;
                btn.textContent = `${categories[cat].completed}/${categories[cat].total} Complete`;
            }
        }
    });
    
    // Master certificate (all 40 complete)
    const masterBtn = document.getElementById('cert-master');
    if (masterBtn) {
        const totalCompleted = appState.completedChallenges.length;
        if (totalCompleted === 40) {
            masterBtn.disabled = false;
            masterBtn.textContent = '🏆 Download Master Certificate';
        } else {
            masterBtn.disabled = true;
            masterBtn.textContent = `${totalCompleted}/40 Complete`;
        }
    }
}
