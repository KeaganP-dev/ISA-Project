// Insert user-facing text from user.js
document.getElementById("registerTitle").innerText = userMessages.registerTitle;
document.getElementById("registerName").placeholder = userMessages.firstNamePlaceholder;
document.getElementById("registerEmail").placeholder = userMessages.emailPlaceholder;
document.getElementById("registerPassword").placeholder = userMessages.passwordPlaceholder;
document.querySelector("button[onclick='register()']").innerText = userMessages.registerButton;

document.getElementById("loginTitle").innerText = userMessages.loginTitle;
document.getElementById("loginEmail").placeholder = userMessages.emailPlaceholder;
document.getElementById("loginPassword").placeholder = userMessages.passwordPlaceholder;
document.querySelector("button[onclick='login()']").innerText = userMessages.loginButton;

async function register() {
    const firstName = document.getElementById('registerName').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;

    try {
        const response = await fetch('https://keaganpurtell.com/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ firstName, email, password })
        });

        const result = await response.text();
        alert(result);
    } catch (error) {
        alert(userMessages.registrationError + error);
    }
}

async function login() {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const response = await fetch('https://keaganpurtell.com/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password }),
            credentials: 'include'
        });
        const result = await response.text();
        alert(result);

        if (response.ok) {
            window.location.href = 'dashboard.html';
        }
    } catch (error) {
        alert(userMessages.loginError + error);
    }
}
