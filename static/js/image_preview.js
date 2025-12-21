document.addEventListener('DOMContentLoaded', (event) => {
            const fileInput = document.getElementById('file_poza');
            const imgPreview = document.getElementById('img_preview');

            if (fileInput && imgPreview) {
                fileInput.addEventListener('change', function (e) {
                    if (e.target.files && e.target.files[0]) {
                        const reader = new FileReader();
                        reader.onload = function (event) {
                            imgPreview.src = event.target.result;
                        };
                        reader.readAsDataURL(e.target.files[0]);
                    }
                });
            }
        });