// Common functionality across pages
document.addEventListener('DOMContentLoaded', function() {
    // Navigation functionality
    const navItems = document.querySelectorAll('.list-group-item');
    navItems.forEach(item => {
        item.addEventListener('click', function(event) {
            event.preventDefault();
            loadPage(this.getAttribute('href'), event);
        });
    });
});

function loadPage(url, event) {
    // Your existing loadPage function...
}
