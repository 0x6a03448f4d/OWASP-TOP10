// Dashboard JavaScript functionality

// Copy to clipboard functionality
function copyToClipboard(text, event) {
    navigator.clipboard.writeText(text).then(() => {
        const btn = event.target.closest('.copy-btn');
        const originalHTML = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-check"></i>';
        btn.style.background = '#5cb85c';
        
        setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.style.background = '';
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

// Smooth scrolling for anchor links
document.addEventListener('DOMContentLoaded', () => {
    // Add smooth scroll behavior
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add animation on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    // Observe all dashboard cards
    document.querySelectorAll('.dashboard-card').forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
        observer.observe(card);
    });

    // Track card clicks for analytics (optional)
    document.querySelectorAll('.dashboard-card').forEach(card => {
        card.addEventListener('click', (e) => {
            if (!e.target.closest('a')) {
                const link = card.querySelector('a');
                if (link) {
                    window.location.href = link.href;
                }
            }
        });
    });

    // Add keyboard navigation
    document.addEventListener('keydown', (e) => {
        if (e.key === '/') {
            e.preventDefault();
            // Future: Add search functionality
            console.log('Search feature - coming soon');
        }
    });
});

// Service Worker registration for offline support (optional enhancement)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        // Uncomment when service worker is implemented
        // navigator.serviceWorker.register('/sw.js')
        //     .then(reg => console.log('Service Worker registered'))
        //     .catch(err => console.log('Service Worker registration failed'));
    });
}

// Add loading states for external resources
window.addEventListener('load', () => {
    document.body.classList.add('loaded');
});

// Handle visibility change to pause animations when tab is not visible
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        document.body.classList.add('hidden');
    } else {
        document.body.classList.remove('hidden');
    }
});

// Export functions for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        copyToClipboard
    };
}
