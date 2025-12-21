// js/custom.js

document.addEventListener("DOMContentLoaded", function() {
    // 1. Găsim checkbox-ul
    const checkbox = document.getElementById("showPasswordcheck");
    
    // 2. Găsim input-ul de parolă
    const passwordInput = document.getElementById("password");
    // Dacă ai și câmp de "Repeat Password", adaugă-l aici:
    // const retypeInput = document.getElementById("exampleRepeatPassword");

    // Verificăm dacă elementele există pe pagină (ca să nu dea eroare pe alte pagini)
    if (checkbox && passwordInput) {
        
        checkbox.onclick = function() {
            if (checkbox.checked) {
                // Afișează parola
                passwordInput.type = "text";
                // if (retypeInput) retypeInput.type = "text";
            } else {
                // Ascunde parola
                passwordInput.type = "password";
                // if (retypeInput) retypeInput.type = "password";
            }
        };
    }
});