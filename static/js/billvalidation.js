// document.addEventListener('DOMContentLoaded', function () {
//     const fileInput = document.getElementById('img_file');
//     const hashValueInput = document.getElementById('hashValue');
//     const uploadForm = document.getElementById('forms');
//
//     fileInput.addEventListener('change', async function () {
//         const file = fileInput.files[0];
//         if (!file) return;
//
//         const hash = await calculateFileHash(file);
//         hashValueInput.value = hash;
//     });
//
//     async function calculateFileHash(file) {
//         const buffer = await file.arrayBuffer();
//         const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
//         const hashArray = new Uint8Array(hashBuffer);
//         const hashHex = Array.from(hashArray)
//             .map(byte => byte.toString(16).padStart(2, '0'))
//             .join('');
//
//         return hashHex;
//     }
// });
// function validateForm() {
//     document.getElementById('img_file_error').style.color = 'red';
//     var img_file = document.getElementById("img_file");
//     var img_file_error = document.getElementById("img_file_error");
//
//     if (img_file.files.length === 0) {
//         img_file_error.innerHTML = "Please select a PDF";
//         return false;
//     } else {
//         var file = img_file.files[0];
//         var fileSizeInMB = file.size / (1024 * 1024); // File size in MB
//         var allowedExtensions = ["pdf"];
//
//         // Get the file extension
//         var fileExtension = file.name.split(".").pop().toLowerCase();
//
//         if (!allowedExtensions.includes(fileExtension)) {
//             img_file_error.innerHTML = "Invalid file type (Only accepts PDF)";
//             return false;
//         } else if (fileSizeInMB > 5) {
//             img_file_error.innerHTML = "File size exceeds 5MB limit";
//             return false;
//         } else {
//             img_file_error.innerHTML = ""; // Clear any previous error messages
//             return true;
//         }
//     }
// }
//
// document.addEventListener('DOMContentLoaded', function () {
//     const form = document.getElementById('forms');
//
//     form.addEventListener('submit', function (event) {
//         // Prevent the default form submission
//         event.preventDefault();
//
//         // Call the validation function
//         if (validateForm()) {
//             // If the validation function returns true, submit the form
//             form.submit();
//         }
//     });
// });
//
// const form = document.getElementById('forms');
//     const submitBtn = document.getElementById('submits');
//
//     form.addEventListener('submit', function (event) {
//         // Prevent form submission
//         event.preventDefault();
//
//         // Disable the submit button to prevent spamming
//         submitBtn.disabled = true;
//         if (submitBtn.disabled == true){img_file_error.innerhtml ='You are being rate limited please wait a few seconds and try again.'}
//         else{img_file_error.innerhtml =''}
//
//         const formData = new FormData(form);
//         fetch('/submit_form', {
//             method: 'POST',
//             body: formData
//         })
//         .then(response => response.json())
//         .then(data => {
//             // Handle the response data if needed
//             console.log(data);
//         })
//         .catch(error => {
//             // Handle any errors if needed
//             console.error(error);
//         })
//         .finally(() => {
//             // Re-enable the submit button after a short delay (e.g., 2 seconds)
//             setTimeout(() => {
//                 submitBtn.disabled = false;
//             }, 15000);
//         });
//     });
//
// // billvalidation.js
//
document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('forms');
    const submitBtn = document.getElementById('submits');
    const imgFile = document.getElementById('img_file');
    const imgFileError = document.getElementById('img_file_error');
    const hashValueInput = document.getElementById('hash_value');

    form.addEventListener('submit', function (event) {
        event.preventDefault(); // Prevent the default form submission

        // Validate the file
        if (validateFile(imgFile, imgFileError)) {
            calculateFileHash(imgFile.files[0])
                .then(hash => {
                    // Set the hash value in the hidden input field
                    hashValueInput.value = hash;

                    // Submit the form
                    form.submit();
                })
                .catch(error => {
                    console.error(error);
                });
        }
    });

    function validateFile(fileInput, errorElement) {
        if (fileInput.files.length === 0) {
            errorElement.innerHTML = "Please select a PDF";
            return false;
        } else {
            const file = fileInput.files[0];
            const fileSizeInMB = file.size / (1024 * 1024);
            const allowedExtensions = ["pdf"];
            const fileExtension = file.name.split(".").pop().toLowerCase();

            if (!allowedExtensions.includes(fileExtension)) {
                errorElement.innerHTML = "Invalid file type (Only accepts PDF)";
                return false;
            } else if (fileSizeInMB > 5) {
                errorElement.innerHTML = "File size exceeds 5MB limit";
                return false;
            } else {
                errorElement.innerHTML = "";
                return true;
            }
        }
    }

    async function calculateFileHash(file) {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = new Uint8Array(hashBuffer);
        const hashHex = Array.from(hashArray)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');

        return hashHex;
    }
});