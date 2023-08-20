window.addEventListener('DOMContentLoaded', (event) => {
  document.getElementById('scroll-button').addEventListener('click', function() {
    window.scrollBy(0, window.innerHeight / 1.5);
  });
});