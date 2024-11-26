// Insert user-facing strings dynamically
document.getElementById('page-title').textContent = 'API Request Summaries';
document.getElementById('page-header').textContent = 'API Request Summaries';

// Endpoint summary section
document.getElementById('endpoint-summary-title').textContent = 'Requests Summary by Endpoint';
document.getElementById('method-column-header').textContent = 'Method';
document.getElementById('endpoint-column-header').textContent = 'Endpoint';
document.getElementById('total-requests-column-header').textContent = 'Total Requests';

// User summary section
document.getElementById('user-summary-title').textContent = 'User Requests Summary';
document.getElementById('user-name-column-header').textContent = 'User Name';
document.getElementById('email-column-header').textContent = 'Email';
document.getElementById('user-total-requests-column-header').textContent = 'Total Requests';
document.getElementById('actions-column-header').textContent = 'Actions';

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
            window.location.href = '/';
        } 

        const data = await response.json();
        
        if (data.role !== "admin") {
            console.log("admin")
            console.log('not admin, redirecting')
            window.location.href = '/dashboard.html';
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        // Redirect to login page in case of an error
        window.location.href = '/';
    }
});


        // Fetch data from the Requests Summary endpoint
        async function fetchRequestsSummary() {
            try {
                const response = await fetch('https://keaganpurtell.com/v1/endpoint-requests', {
                    method: 'GET',
                    credentials: 'include',
                });
                if (!response.ok) {
                    throw new Error(`Failed to fetch requests summary: ${response.statusText}`);
                }
                const data = await response.json();
                populateTable('requests-summary-table', data);
            } catch (error) {
                console.error('Error fetching requests summary:', error);
            }
        }

        // Fetch data from the User Requests Summary endpoint
        async function fetchUserRequestsSummary() {
            try {
                const response = await fetch('https://keaganpurtell.com/v1/user-requests', {
                    method: 'GET',
                    credentials: 'include',
                });
                if (!response.ok) {
                    throw new Error(`Failed to fetch user requests summary: ${response.statusText}`);
                }
                const data = await response.json();
                populateTable('user-requests-summary-table', data);
            } catch (error) {
                console.error('Error fetching user requests summary:', error);
            }
        }

// Populate a table with data
function populateTable(tableId, data) {
    const tableBody = document.getElementById(tableId).querySelector('tbody');
    tableBody.innerHTML = ''; // Clear any existing rows

    data.forEach(row => {
        const tr = document.createElement('tr');

        // Add table cells for user data
        Object.values(row).forEach(cellData => {
            const td = document.createElement('td');
            td.textContent = cellData;
            tr.appendChild(td);
        });

        if (tableId === 'user-requests-summary-table') {
            // Add a new column for actions (Edit and Delete buttons)
            const actionsTd = document.createElement('td');

            // Edit button
            const editButton = document.createElement('button');
            editButton.textContent = 'Edit';
            editButton.onclick = () => editUser(row.email); // Use the user's email
            actionsTd.appendChild(editButton);

            // Delete button
            const deleteButton = document.createElement('button');
            deleteButton.textContent = 'Delete';
            deleteButton.onclick = () => deleteUser(row.email); // Use the user's email
            actionsTd.appendChild(deleteButton);

            tr.appendChild(actionsTd);
        }

        tableBody.appendChild(tr);
    });
}

// Edit user function
async function editUser(email) {
    const newEmail = prompt(`Enter new email for ${email}:`);
    // Email validation using a simple regular expression
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (newEmail) {
        if (!emailRegex.test(newEmail)) {
            alert("Please enter a valid email address.");
            return; // Stop the function if the email is invalid
        }

        try {
            const response = await fetch(`https://keaganpurtell.com/v1/users/${encodeURIComponent(email)}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({ newEmail }),
            });

            if (response.ok) {
                alert(`User ${email} updated successfully!`);
                fetchUserRequestsSummary(); // Refresh the table
            } else {
                throw new Error(`Failed to update user: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Error updating user:', error);
            alert('An error occurred while updating the user.');
        }
    }
}

// Delete user function
async function deleteUser(email) {
    if (confirm(`Are you sure you want to delete the user with email ${email}?`)) {
        try {
            const response = await fetch(`https://keaganpurtell.com/v1/users/${encodeURIComponent(email)}`, {
                method: 'DELETE',
                credentials: 'include',
            });

            if (response.ok) {
                alert(`User ${email} deleted successfully!`);
                fetchUserRequestsSummary(); // Refresh the table
            } else {
                throw new Error(`Failed to delete user: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            alert('An error occurred while deleting the user.');
        }
    }
}

// Load the tables when the page is loaded
document.addEventListener('DOMContentLoaded', () => {
    fetchRequestsSummary();
    fetchUserRequestsSummary();
});
