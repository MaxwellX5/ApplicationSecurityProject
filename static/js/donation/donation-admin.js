// when user selects the file, do these
document.getElementById('img_file').addEventListener('change', function (e) {
  var img = document.getElementById('image-preview');
  // create blob from the image file, then put that as the src of the thing
  img.src = URL.createObjectURL(e.target.files[0]);
  img.className = 'border rounded w-100 p-2'
  img.height = img.width
}, false);

// maintain aspect ratio of image-preview
window.addEventListener('resize', function() {
  var img = document.getElementById('image-preview');
  img.height = img.width
});

window.addEventListener('DOMContentLoaded', (event) => {
  // Get all comment textareas
  let commentTextareas = document.querySelectorAll('[id^="comment-"]');

  // Iterate through each textarea and set the value from the data-comment attribute
  commentTextareas.forEach(textarea => {
      textarea.value = textarea.dataset.comment;
  });
});

window.addEventListener('DOMContentLoaded', (event) => {
  let radioButtons = document.querySelectorAll('[name^="points-update-"]');

  radioButtons.forEach(radioButton => {
      let targetField = document.getElementById(radioButton.dataset.toggleField);

      // Initially disable the target field
      targetField.disabled = true;

      // Function to enable/disable the target field
      let toggleTargetField = () => {
          targetField.disabled = (radioButton.value === 'True' && radioButton.checked);
      }

      // Add the event listener for future changes
      radioButton.addEventListener('change', toggleTargetField);
  });
});

window.addEventListener('DOMContentLoaded', (event) => {
  // Get all textareas starting with 'rewards-description-'
  let textareas = document.querySelectorAll('textarea[id^="rewards-description-"]');

  textareas.forEach(textarea => {
      // Get the description from the data attribute
      let description = textarea.dataset.comment;

      // Assign the description to the textarea
      textarea.value = description;
  });
});

window.addEventListener('DOMContentLoaded', (event) => {
  // Get all the image file inputs
  let imgFileInputs = document.querySelectorAll('[id^="img_file-"]');
  
  imgFileInputs.forEach(input => {
    // Extract the level from the id
    let level = input.id.split('-')[1];
  
    // Find the corresponding image preview element
    let img = document.querySelector(`#image-preview-${level}`);
  
    // Add the event listener to the file input
    input.addEventListener('change', function (e) {
      // Create blob from the image file, then put that as the src of the image
      img.src = URL.createObjectURL(e.target.files[0]);
      img.className = 'border rounded w-100 p-2'
      img.height = img.width
    }, false);
  });
});

document.addEventListener('DOMContentLoaded', function() {
  // get all checkboxes
  var checkboxes = document.querySelectorAll('.profanity-enabled');

  // function to enable save buttons
  var enableSubmitButtons = function() {
    var submitButtons = document.querySelectorAll('.profanities-submit');
    submitButtons.forEach(function(button) {
      button.disabled = false;
    });
  };

  // add event listener to each checkbox
  checkboxes.forEach(function(checkbox) {
    checkbox.addEventListener('change', enableSubmitButtons);
  });
});

// script for tooltip
const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))