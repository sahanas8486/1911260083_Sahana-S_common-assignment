// Simple client-side helpers for the Firewall Monitoring System

document.addEventListener('DOMContentLoaded', function () {
    // Auto-hide flash messages after 4 seconds
    const flashes = document.querySelectorAll('.alert');
    flashes.forEach(function (el) {
        setTimeout(function () {
            el.style.transition = 'opacity 0.4s';
            el.style.opacity = '0';
            setTimeout(function () { el.remove(); }, 400);
        }, 4000);
    });
});
