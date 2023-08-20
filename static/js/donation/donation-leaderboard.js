document.addEventListener('DOMContentLoaded', (event) => {
  // Select the progress bar element
  const progressBar = document.querySelector('#donation-progress-bar');

  // Get the progress value from the data attribute
  const progressValue = progressBar.dataset.progress;

  // Set the width of the progress bar
  progressBar.style.width = `${progressValue}%`;
});

document.addEventListener('DOMContentLoaded', (event) => {
  // function for scrolling the rewards card container
  // scroll the pixels
  const scrollAmount = 420;

  // select the elements
  const scrollContainer = document.querySelector('#rewards-cards');
  const scrollLeftBtn = document.querySelector('#scroll-left');
  const scrollRightBtn = document.querySelector('#scroll-right');

  // scroll left
  scrollLeftBtn.addEventListener('click', () => {
    scrollContainer.scrollBy({left: -scrollAmount, behavior: 'smooth'});
  });

  // scroll right
  scrollRightBtn.addEventListener('click', () => {
    scrollContainer.scrollBy({left: scrollAmount, behavior: 'smooth'});
  });

  // function for moving container using mouse
  let isDown = false;
  let startX;
  let scrollLeftPosition;

  // get position when click down
  scrollContainer.addEventListener('mousedown', (e) => {
      isDown = true;
      startX = e.pageX - scrollContainer.offsetLeft;
      scrollLeftPosition = scrollContainer.scrollLeft;
  });

  scrollContainer.addEventListener('mouseleave', () => {
      isDown = false;
  });

  scrollContainer.addEventListener('mouseup', () => {
      isDown = false;
  });

  // when click is down, start moving
  scrollContainer.addEventListener('mousemove', (e) => {
      if(!isDown) return;
      e.preventDefault();
      const x = e.pageX - scrollContainer.offsetLeft;
      const walk = (x - startX); //scroll-fast
      scrollContainer.scrollLeft = scrollLeftPosition - walk;
  });

  // Set background images for cards
  document.querySelectorAll('.custom-bg').forEach(element => {
    element.style.backgroundImage = `url(${element.dataset.bg})`;
  });
});

const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]')
const popoverList = [...popoverTriggerList].map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl))
const popover = new bootstrap.Popover('.popover-dismiss', {
  trigger: 'focus'
})

const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))