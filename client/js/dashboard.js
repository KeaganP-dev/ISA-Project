// Populate user-facing text on the dashboard page
document.getElementById("seeUserDetails").innerText = userMessages.seeUserDetailsButton;
document.getElementById("adminTab").innerText = userMessages.adminInfoTab;
document.getElementById("dashboardWelcome").innerText = userMessages.dashboardWelcome;
document.getElementById("dashboardText").innerText = userMessages.dashboardText;
document.getElementById("userInput").placeholder = userMessages.userInputPlaceholder;
document.getElementById("submitButton").innerText = userMessages.submitButton;
document.getElementById("adminDashboardTitle").innerText = userMessages.adminDashboardTitle;
document.getElementById("adminName").innerText = userMessages.adminName;
document.getElementById("adminEmail").innerText = userMessages.adminEmail;
document.getElementById("adminApiCalls").innerText = userMessages.adminApiCalls;

document.getElementById('seeUserDetails').addEventListener('click', async () => {
    try {
        const response = await fetch('https://keaganpurtell.com/users', {
            method: 'GET',
            credentials: 'include'
        });

        if (response.ok) {
            const users = await response.json();
            const userDetailsDiv = document.getElementById('userDetails');
            userDetailsDiv.innerHTML = ''; // Clear previous details

            users.forEach(user => {
                const userDetail = `<p>Name: ${user.first_name}, Email: ${user.email}, Requests: ${user.requests}</p>`;
                userDetailsDiv.innerHTML += userDetail;
            });
        } else {
            console.error(userMessages.fetchUserError, await response.text());
            alert(userMessages.fetchUserError);
        }
    } catch (error) {
        console.error('Error:', error);
        alert(userMessages.fetchUserError);
    }
});

async function handleSubmit() {
    const userInput = document.getElementById('userInput').value;
    if (!userInput) {
        alert(userMessages.userInputPlaceholder);
        return;
    }

    try {
        const response = await fetch(`https://keaganpurtell.com/predict/${userInput}`, {
            method: 'GET',
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            alert(`Prediction data: ${JSON.stringify(data)}`);
            if (data.warning) {
                alert(data.warning);
            }
        } else {
            console.error(userMessages.fetchPredictionError, await response.text());
            alert(userMessages.fetchPredictionError);
        }
    } catch (error) {
        console.error(userMessages.fetchPredictionError, error);
        alert(userMessages.fetchPredictionError);
    }
}

function showContent(contentId) {
    document.querySelectorAll('.content').forEach(content => content.classList.remove('active'));
    document.getElementById(contentId).classList.add('active');
}
