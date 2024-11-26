// Populate user-facing text on the dashboard page
document.getElementById("adminTab").innerText = userMessages.adminInfoTab;
document.getElementById("dashboardWelcome").innerText = userMessages.dashboardWelcome;
document.getElementById("dashboardText").innerText = userMessages.dashboardText;
document.getElementById("userInput").placeholder = userMessages.userInputPlaceholder;
document.getElementById("adminDashboardTitle").innerText = userMessages.adminDashboardTitle;
document.getElementById("adminName").innerText = userMessages.adminName;
document.getElementById("adminEmail").innerText = userMessages.adminEmail;
document.getElementById("adminApiCalls").innerText = userMessages.adminApiCalls;


document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Check if the user is authenticated
        const response = await fetch('https://keaganpurtell.com/v1/auth-check', {
            method: 'GET',
            credentials: 'include', // Include cookies for session validation
        });

        if (!response.ok) {
            // If the user is not authenticated, redirect to the login page
            console.warn('User not authenticated. Redirecting to login...');
            console.log('not authenticated, redirecting')
            window.location.href = '/';
        } 

        const data = await response.json();
        
        if (data.role === "admin") {
            console.log("admin")
            const adminTab = document.getElementById('adminTab');
            adminTab.style.display = 'block'; // Make the Admin button visible
        }
        console.log(response)
        console.log('not admin')
    } catch (error) {
        console.error('Error checking authentication:', error);
        // Redirect to login page in case of an error
        window.location.href = '/';
    }
});

async function getTickerSummary() {
    const ticker = document.getElementById('userInput').value;
    if (!ticker) {
        alert('Please enter a ticker symbol.');
        return;
    }

    try {
        const response = await fetch(`https://keaganpurtell.com/v1/summary-info/${ticker}`, {
            method: 'GET',
            credentials: 'include',
        });

        if (response.ok) {
            const data = await response.json();
            alert(`Summary Info for ${ticker}: ${JSON.stringify(data)}`);
        } else {
            const errorText = await response.text();
            console.error('Error fetching summary info:', errorText);
            alert('Error fetching summary info. Please try again.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error fetching summary info. Please check your network and try again.');
    }
}
async function getRSIData() {
    const ticker = document.getElementById('userInput').value;
    if (!ticker) {
        alert('Please enter a ticker symbol.');
        return;
    }

    try {
        const response = await fetch(`https://keaganpurtell.com/v1/rsi/${ticker}`, {
            method: 'GET',
            credentials: 'include',
        });

        if (response.ok) {
            const data = await response.json();
            alert(`RSI Data for ${ticker}: ${JSON.stringify(data)}`);
        } else {
            const errorText = await response.text();
            console.error('Error fetching RSI data:', errorText);
            alert('Error fetching RSI data. Please try again.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error fetching RSI data. Please check your network and try again.');
    }
}

async function getPrediction() {
    const ticker = document.getElementById('userInput').value;
    if (!ticker) {
        alert('Please enter a ticker symbol.');
        return;
    }

    try {
        const response = await fetch(`https://keaganpurtell.com/v1/predict/${ticker}`, {
            method: 'GET',
            credentials: 'include',
        });

        if (response.ok) {
            const data = await response.json();
            alert(`Prediction for ${ticker}: ${JSON.stringify(data)}`);
        } else {
            const errorText = await response.text();
            console.error('Error fetching prediction:', errorText);
            alert('Error fetching prediction. Please try again.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error fetching prediction. Please check your network and try again.');
    }
}
async function fetchApiConsumption() {
    const apiConsumptionElement = document.getElementById('apiConsumption');
    apiConsumptionElement.innerText = 'Fetching your API usage...'; // Show a loading message

    try {
        const response = await fetch('https://keaganpurtell.com/v1/api-consumption', {
            method: 'GET',
            credentials: 'include',
        });

        if (response.ok) {
            const data = await response.json();
            console.log(data.totalRequests);
            console.log(data);
            apiConsumptionElement.innerText = `Total API Requests Used: ${data.totalRequests}`;
        } else {
            const errorText = await response.text();
            console.error('Error fetching API consumption:', errorText);
            apiConsumptionElement.innerText = 'Error fetching API usage. Please try again.';
        }
    } catch (error) {
        console.error('Error:', error);
        apiConsumptionElement.innerText = 'Error fetching API usage. Please check your connection.';
    }
}
function showContent(contentId) {
    document.querySelectorAll('.content').forEach(content => content.classList.remove('active'));
    document.getElementById(contentId).classList.add('active');
}
