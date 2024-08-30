// small js file that grows elements when hovering over them

document.querySelectorAll('.growable').forEach(function(badge) {
    badge.addEventListener('mouseover', function() {
        this.style.transform = 'scale(1.1)';
    });

    badge.addEventListener('mouseout', function() {
        this.style.transform = 'scale(1)';
    });
});