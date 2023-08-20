
document.addEventListener('DOMContentLoaded', function() {
  var checkbox = document.getElementById('2FAStatus');
  var hiddenInput = document.getElementById('hidden2FAStatus'); // Use the correct ID here
  var label = document.getElementById('2FALabel');
  var facecheckbox = document.getElementById('Face2FAStatus');
  var faceLabel = document.getElementById('Face2FALabel');
  var faceHiddenInput = document.getElementById('hiddenFace2FAStatus');

  checkbox.addEventListener('change', function() {
    if (this.checked) {
      label.textContent = 'Disable OTP 2FA';
      hiddenInput.value = 'on'; // Set the value to 'on' when the checkbox is checked
      faceHiddenInput.value = 'off';
      faceLabel.textContent = 'Enable Face 2FA';
      facecheckbox.checked = false;

    } else {
      label.textContent = 'Enable OTP 2FA';
      hiddenInput.value = 'off'; // Set the value to 'off' when the checkbox is unchecked
    }
  });
});

document.addEventListener('DOMContentLoaded', function() {
  var checkbox = document.getElementById('Face2FAStatus');
  var hiddenInput = document.getElementById('hiddenFace2FAStatus'); // Use the correct ID here
  var label = document.getElementById('Face2FALabel');
  var otpcheckbox = document.getElementById('2FAStatus');
  var otpLabel = document.getElementById('2FALabel');
  var otpHiddenInput = document.getElementById('hidden2FAStatus');

  checkbox.addEventListener('change', function() {
    if (this.checked) {
      label.textContent = 'Disable Face 2FA';
      hiddenInput.value = 'on'; // Set the value to 'on' when the checkbox is checked
      otpHiddenInput.value = 'off';
      otpLabel.textContent = 'Enable OTP 2FA';
      otpcheckbox.checked = false;
    } else {
      label.textContent = 'Enable Face 2FA';
      hiddenInput.value = 'off'; // Set the value to 'off' when the checkbox is unchecked
    }
  });
});



document.addEventListener('DOMContentLoaded', function() {
    // Add event listener to the "image-file" element
    document.getElementById('image-file').addEventListener('change', function(e) {
      // Your logic for handling the file change event goes here
      var img = document.getElementById('image-preview');
      // create blob from the image file, then put that as the src of the thing
      img.src = URL.createObjectURL(e.target.files[0]);
    });
  });
