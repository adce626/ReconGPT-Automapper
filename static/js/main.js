/**
 * ReconGPT Main JavaScript
 * Common functionality for the web interface
 */

// Global variables
let refreshInterval = null;

/**
 * Initialize common functionality when DOM is loaded
 */
document.addEventListener('DOMContentLoaded', function() {
    initializeTooltips();
    initializeAutoRefresh();
    initializeFormValidation();
    initializeKeyboardShortcuts();
});

/**
 * Initialize Bootstrap tooltips
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Initialize auto-refresh for active scans
 */
function initializeAutoRefresh() {
    const activeScansElement = document.querySelector('[data-active-scans]');
    if (activeScansElement) {
        const activeScans = parseInt(activeScansElement.getAttribute('data-active-scans'));
        if (activeScans > 0) {
            startAutoRefresh();
        }
    }
}

/**
 * Start auto-refresh for active scans
 */
function startAutoRefresh() {
    if (refreshInterval) return; // Already running
    
    refreshInterval = setInterval(() => {
        // Check if we're still on a page that needs refreshing
        const activeScansElement = document.querySelector('[data-active-scans]');
        if (activeScansElement) {
            const activeScans = parseInt(activeScansElement.getAttribute('data-active-scans'));
            if (activeScans > 0) {
                location.reload();
            } else {
                stopAutoRefresh();
            }
        } else {
            stopAutoRefresh();
        }
    }, 30000); // Refresh every 30 seconds
    
    // Show refresh indicator
    showRefreshIndicator();
}

/**
 * Stop auto-refresh
 */
function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
        hideRefreshIndicator();
    }
}

/**
 * Show refresh indicator
 */
function showRefreshIndicator() {
    const indicator = document.createElement('div');
    indicator.id = 'refresh-indicator';
    indicator.className = 'position-fixed top-0 end-0 m-3 alert alert-info alert-dismissible fade show';
    indicator.style.zIndex = '9999';
    indicator.innerHTML = `
        <i class="fas fa-sync-alt fa-spin me-2"></i>
        Auto-refreshing for active scans...
        <button type="button" class="btn-close" onclick="stopAutoRefresh()"></button>
    `;
    document.body.appendChild(indicator);
}

/**
 * Hide refresh indicator
 */
function hideRefreshIndicator() {
    const indicator = document.getElementById('refresh-indicator');
    if (indicator) {
        indicator.remove();
    }
}

/**
 * Initialize form validation
 */
function initializeFormValidation() {
    const forms = document.querySelectorAll('form[data-validate="true"]');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!validateForm(form)) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
}

/**
 * Validate form fields
 */
function validateForm(form) {
    let isValid = true;
    
    // Validate target domain
    const targetInput = form.querySelector('input[name="target"]');
    if (targetInput) {
        const target = targetInput.value.trim();
        if (!isValidDomain(target)) {
            showFieldError(targetInput, 'Please enter a valid domain name');
            isValid = false;
        } else {
            clearFieldError(targetInput);
        }
    }
    
    // Validate scan name
    const nameInput = form.querySelector('input[name="scan_name"]');
    if (nameInput) {
        const name = nameInput.value.trim();
        if (name.length < 3) {
            showFieldError(nameInput, 'Scan name must be at least 3 characters long');
            isValid = false;
        } else {
            clearFieldError(nameInput);
        }
    }
    
    // Validate tool selection
    const toolCheckboxes = form.querySelectorAll('input[name="tools"]:checked');
    if (toolCheckboxes.length === 0) {
        const toolsContainer = form.querySelector('.form-check');
        if (toolsContainer) {
            showValidationMessage('Please select at least one reconnaissance tool');
            isValid = false;
        }
    }
    
    return isValid;
}

/**
 * Check if a string is a valid domain
 */
function isValidDomain(domain) {
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
    return domainRegex.test(domain) && domain.length <= 253;
}

/**
 * Show field error message
 */
function showFieldError(field, message) {
    field.classList.add('is-invalid');
    
    let feedback = field.parentNode.querySelector('.invalid-feedback');
    if (!feedback) {
        feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        field.parentNode.appendChild(feedback);
    }
    feedback.textContent = message;
}

/**
 * Clear field error message
 */
function clearFieldError(field) {
    field.classList.remove('is-invalid');
    const feedback = field.parentNode.querySelector('.invalid-feedback');
    if (feedback) {
        feedback.remove();
    }
}

/**
 * Show validation message
 */
function showValidationMessage(message, type = 'danger') {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show mt-3`;
    alert.innerHTML = `
        <i class="fas fa-exclamation-triangle me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Insert at the top of the main container
    const main = document.querySelector('main.container');
    if (main) {
        main.insertBefore(alert, main.firstChild);
    }
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (alert.parentNode) {
            alert.remove();
        }
    }, 5000);
}

/**
 * Initialize keyboard shortcuts
 */
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(event) {
        // Ctrl/Cmd + N: New scan
        if ((event.ctrlKey || event.metaKey) && event.key === 'n') {
            event.preventDefault();
            const newScanModal = document.getElementById('newScanModal');
            if (newScanModal) {
                const modal = new bootstrap.Modal(newScanModal);
                modal.show();
            }
        }
        
        // Ctrl/Cmd + R: Reports
        if ((event.ctrlKey || event.metaKey) && event.key === 'r') {
            event.preventDefault();
            window.location.href = '/reports';
        }
        
        // Escape: Close modals
        if (event.key === 'Escape') {
            const modals = document.querySelectorAll('.modal.show');
            modals.forEach(modal => {
                const modalInstance = bootstrap.Modal.getInstance(modal);
                if (modalInstance) {
                    modalInstance.hide();
                }
            });
        }
    });
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text, button = null) {
    navigator.clipboard.writeText(text).then(() => {
        if (button) {
            const originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check me-1"></i>Copied!';
            button.classList.remove('btn-outline-secondary');
            button.classList.add('btn-success');
            
            setTimeout(() => {
                button.innerHTML = originalText;
                button.classList.remove('btn-success');
                button.classList.add('btn-outline-secondary');
            }, 2000);
        } else {
            showValidationMessage('Copied to clipboard!', 'success');
        }
    }).catch(err => {
        console.error('Failed to copy text: ', err);
        showValidationMessage('Failed to copy to clipboard', 'danger');
    });
}

/**
 * Format timestamp
 */
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Format file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Debounce function for search inputs
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Search functionality for tables
 */
function initializeTableSearch(tableId, searchInputId) {
    const table = document.getElementById(tableId);
    const searchInput = document.getElementById(searchInputId);
    
    if (!table || !searchInput) return;
    
    const debouncedSearch = debounce((searchTerm) => {
        const rows = table.querySelectorAll('tbody tr');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            const matches = text.includes(searchTerm.toLowerCase());
            row.style.display = matches ? '' : 'none';
        });
    }, 300);
    
    searchInput.addEventListener('input', (e) => {
        debouncedSearch(e.target.value);
    });
}

/**
 * Export data as JSON
 */
function exportAsJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json'
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Export data as CSV
 */
function exportAsCSV(data, headers, filename) {
    const csvContent = [
        headers.join(','),
        ...data.map(row => headers.map(header => `"${row[header] || ''}"`).join(','))
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Show loading spinner
 */
function showLoading(element, text = 'Loading...') {
    const spinner = document.createElement('div');
    spinner.className = 'text-center py-4';
    spinner.innerHTML = `
        <div class="spinner-border text-primary mb-3" role="status"></div>
        <div class="text-muted">${text}</div>
    `;
    
    element.innerHTML = '';
    element.appendChild(spinner);
}

/**
 * Hide loading spinner and restore content
 */
function hideLoading(element, content) {
    element.innerHTML = content;
}

/**
 * Animate number counting
 */
function animateNumber(element, start, end, duration = 1000) {
    const startTime = performance.now();
    const startValue = start;
    const endValue = end;
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const currentValue = Math.floor(startValue + (endValue - startValue) * progress);
        element.textContent = currentValue.toLocaleString();
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

/**
 * Initialize number animations for statistics cards
 */
function initializeNumberAnimations() {
    const numberElements = document.querySelectorAll('[data-animate-number]');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const element = entry.target;
                const endValue = parseInt(element.textContent.replace(/,/g, ''));
                animateNumber(element, 0, endValue);
                observer.unobserve(element);
            }
        });
    });
    
    numberElements.forEach(el => observer.observe(el));
}

// Initialize number animations when DOM is loaded
document.addEventListener('DOMContentLoaded', initializeNumberAnimations);

/**
 * Theme toggle functionality (if needed in the future)
 */
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    html.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

/**
 * Load saved theme on page load
 */
function loadSavedTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-bs-theme', savedTheme);
    }
}

// Load theme when DOM is loaded
document.addEventListener('DOMContentLoaded', loadSavedTheme);
