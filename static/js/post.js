document.addEventListener("DOMContentLoaded", function() {
  var clearButton = document.getElementById("clearButton");
  clearButton.addEventListener("click", submitClearForm);
});

function submitClearForm() {
  document.getElementById('clearMissionForm').submit();
}