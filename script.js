function login() {
    alert("Login clicked (Backend will be added later)");
    window.location.href = "dashboard.html";
}

function register() {
    alert("Register clicked (Backend will be added later)");
    window.location.href = "login.html";
}

function reportIncident() {
    alert("Incident reporting page coming soon!");
}

function viewReports() {
    alert("Reports page coming soon!");
}

function goToReport() {
    window.location.href = "report.html";
}

function submitIncident() {
    let type = document.getElementById("type").value;
    let description = document.getElementById("description").value;

    if (type === "" || description === "") {
        alert("Please fill all fields");
        return;
    }

    
    let incident = {
        type: type,
        description: description,
        date: new Date().toLocaleString()
    };

    console.log("Incident Submitted:", incident);

    alert("Incident reported successfully!");

    window.location.href = "dashboard.html";
}