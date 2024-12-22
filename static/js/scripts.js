document.addEventListener('DOMContentLoaded', function() {
    // Add any JavaScript code needed for interactivity
    console.log('Chalo Site loaded successfully');

    // Device ID Management
    function getDeviceFingerprint() {
        const screenPrint = `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`;
        const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const language = navigator.language;
        const platform = navigator.platform;
        
        return btoa(`${screenPrint}-${timeZone}-${language}-${platform}`);
    }

    // Store device fingerprint in localStorage
    if (!localStorage.getItem('deviceFingerprint')) {
        localStorage.setItem('deviceFingerprint', getDeviceFingerprint());
    }

    // File Preview
    function previewFile(input) {
        if (input.files && input.files[0]) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const preview = document.getElementById('file-preview');
                if (preview) {
                    preview.src = e.target.result;
                }
            };
            reader.readAsDataURL(input.files[0]);
        }
    }

    // Password Strength Meter
    function updatePasswordStrength(password) {
        const strengthMeter = document.getElementById('password-strength');
        if (!strengthMeter) return;

        let strength = 0;
        if (password.length >= 8) strength++;
        if (password.match(/[a-z]+/)) strength++;
        if (password.match(/[A-Z]+/)) strength++;
        if (password.match(/[0-9]+/)) strength++;
        if (password.match(/[^A-Za-z0-9]+/)) strength++;

        const strengthText = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'];
        const strengthClass = ['danger', 'warning', 'info', 'primary', 'success'];
        
        strengthMeter.textContent = strengthText[strength - 1] || '';
        strengthMeter.className = `text-${strengthClass[strength - 1] || 'danger'}`;
    }

    // Flash Message Auto-dismiss
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        if (!alert.classList.contains('alert-danger')) {
            setTimeout(() => {
                alert.style.transition = 'opacity 0.5s ease';
                alert.style.opacity = '0';
                setTimeout(() => alert.remove(), 500);
            }, 5000);
        }
    });

    // File Upload Size Validation
    function validateFileSize(input) {
        if (input.files && input.files[0]) {
            if (input.files[0].size > 16 * 1024 * 1024) { // 16MB
                alert('File size exceeds 16MB limit');
                input.value = '';
                return false;
            }
        }
        return true;
    }

    // Payment Method Selection
    function updatePaymentFields(method) {
        const paypalFields = document.getElementById('paypal-fields');
        const mpesaFields = document.getElementById('mpesa-fields');
        
        if (paypalFields && mpesaFields) {
            if (method === 'paypal') {
                paypalFields.style.display = 'block';
                mpesaFields.style.display = 'none';
            } else if (method === 'mpesa') {
                paypalFields.style.display = 'none';
                mpesaFields.style.display = 'block';
            }
        }
    }

    // Initialize tooltips and popovers
    $(function () {
        $('[data-toggle="tooltip"]').tooltip();
        $('[data-toggle="popover"]').popover();
    });
});
