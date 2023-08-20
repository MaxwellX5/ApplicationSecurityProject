document.addEventListener("DOMContentLoaded", function () {
  function togglePassword(event) {
    const passwordField = document.querySelector("input[name='password']");
    const eyeIcon = this.querySelector("i");

    if (passwordField.type === "password") {
      passwordField.type = "text";
      eyeIcon.classList.remove("fa-eye");
      eyeIcon.classList.add("fa-eye-slash");
    } else {
      passwordField.type = "password";
      eyeIcon.classList.remove("fa-eye-slash");
      eyeIcon.classList.add("fa-eye");
    }
  }

  const toggleButton = document.getElementById("toggle-password");
  toggleButton.addEventListener("click", togglePassword);
});

document.addEventListener("DOMContentLoaded", function () {
  function toggleCurrentPassword(event) {
    const passwordField = document.querySelector("input[name='currentpassword']");
    const eyeIcon = this.querySelector("i");

    if (passwordField.type === "password") {
      passwordField.type = "text";
      eyeIcon.classList.remove("fa-eye");
      eyeIcon.classList.add("fa-eye-slash");
    } else {
      passwordField.type = "password";
      eyeIcon.classList.remove("fa-eye-slash");
      eyeIcon.classList.add("fa-eye");
    }
  }

  const toggleButton = document.getElementById("toggle-currentpassword");
  toggleButton.addEventListener("click", toggleCurrentPassword);
});

document.addEventListener("DOMContentLoaded", function () {
  function toggleConfirmPassword(event) {
    const passwordField = document.querySelector("input[name='confirm_password']");
    const eyeIcon = this.querySelector("i");

    if (passwordField.type === "password") {
      passwordField.type = "text";
      eyeIcon.classList.remove("fa-eye");
      eyeIcon.classList.add("fa-eye-slash");
    } else {
      passwordField.type = "password";
      eyeIcon.classList.remove("fa-eye-slash");
      eyeIcon.classList.add("fa-eye");
    }
  }

  const toggleButton = document.getElementById("toggle-confirm_password");
  toggleButton.addEventListener("click", toggleConfirmPassword);
});

document.addEventListener("DOMContentLoaded", function () {
  function toggleRePassword(event) {
    const passwordField = document.querySelector("input[name='repassword']");
    const eyeIcon = this.querySelector("i");

    if (passwordField.type === "password") {
      passwordField.type = "text";
      eyeIcon.classList.remove("fa-eye");
      eyeIcon.classList.add("fa-eye-slash");
    } else {
      passwordField.type = "password";
      eyeIcon.classList.remove("fa-eye-slash");
      eyeIcon.classList.add("fa-eye");
    }
  }

  const toggleButton = document.getElementById("toggle-repassword");
  toggleButton.addEventListener("click", toggleRePassword);
});

document.addEventListener("DOMContentLoaded", function () {
  function toggleNewPassword(event) {
    const passwordField = document.querySelector("input[name='newpassword']");
    const eyeIcon = this.querySelector("i");

    if (passwordField.type === "password") {
      passwordField.type = "text";
      eyeIcon.classList.remove("fa-eye");
      eyeIcon.classList.add("fa-eye-slash");
    } else {
      passwordField.type = "password";
      eyeIcon.classList.remove("fa-eye-slash");
      eyeIcon.classList.add("fa-eye");
    }
  }

  const toggleButton = document.getElementById("toggle-new_password");
  toggleButton.addEventListener("click", toggleNewPassword);
});


// function toggleConfirmPassword() {
//     const passwordField = document.querySelector("input[name='confirm_password']");
//     if (passwordField.type === "password") {
//       passwordField.type = "text";
//       document.querySelector(".toggle-confirm_password i").classList.remove("fa-eye");
//       document.querySelector(".toggle-confirm_password i").classList.add("fa-eye-slash");
//     } else {
//       passwordField.type = "password";
//       document.querySelector(".toggle-confirm_password i").classList.remove("fa-eye-slash");
//       document.querySelector(".toggle-confirm_password i").classList.add("fa-eye");
//     }
// }
//
// function toggleRePassword() {
//     const passwordField = document.querySelector("input[name='repassword']");
//     if (passwordField.type === "password") {
//       passwordField.type = "text";
//       document.querySelector(".toggle-repassword i").classList.remove("fa-eye");
//       document.querySelector(".toggle-repassword i").classList.add("fa-eye-slash");
//     } else {
//       passwordField.type = "password";
//       document.querySelector(".toggle-repassword i").classList.remove("fa-eye-slash");
//       document.querySelector(".toggle-repassword i").classList.add("fa-eye");
//     }
// }
//
// function toggleNewPassword() {
//     const passwordField = document.querySelector("input[name='newpassword']");
//     if (passwordField.type === "password") {
//       passwordField.type = "text";
//       document.querySelector(".toggle-newpassword i").classList.remove("fa-eye");
//       document.querySelector(".toggle-newpassword i").classList.add("fa-eye-slash");
//     } else {
//       passwordField.type = "password";
//       document.querySelector(".toggle-newpassword i").classList.remove("fa-eye-slash");
//       document.querySelector(".toggle-newpassword i").classList.add("fa-eye");
//     }
// }
