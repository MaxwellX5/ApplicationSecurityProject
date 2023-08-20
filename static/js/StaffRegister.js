function submitFormWithCaptcha() {
  grecaptcha.ready(function() {
    grecaptcha.execute('6LezYBkmAAAAAHdNAgPTnZ2S2DQ2FobvTO5xILZO', {action: 'staffregister'}).then(function(token) {
      // Add the token to your form as a hidden field
      document.getElementById("g-captcha-response").value = token;

      // Submit your form
      document.getElementById("register-form").submit();
    });
  });
}

document.addEventListener("DOMContentLoaded", function() {
    // Add the event listener to the submit button
    document.getElementById("submit-button").addEventListener("click", function(event) {
      event.preventDefault(); // Prevent the form from submitting directly
      submitFormWithCaptcha();
    });
  });

