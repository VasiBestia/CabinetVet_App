document.addEventListener('DOMContentLoaded', (event) => {
            const today = new Date().toISOString().split('T')[0];
            const dateInputs = document.querySelectorAll('input[name="data_vizita"]');
            dateInputs.forEach(input => {
                if (!input.value) input.value = today;
            });
        });