document.getElementById("generateResult").addEventListener("click", function () {

    // Step 1
    const useCase = document.getElementById("useCase").value;
    const sensitivity = document.getElementById("sensitivity").value;
    const deployment = document.getElementById("deployment").value;

    // Step 2
    const threatLevel = document.getElementById("threatLevel").value;
    const adversary = document.getElementById("adversary").value;
    const timeframe = document.getElementById("timeframe").value;

    // Step 3
    const performance = document.getElementById("performancepriority").value;
    const hardware = document.getElementById("hardware").value;
    const dataVolume = document.getElementById("dataVolume").value;

    // Step 4
    const compliance = document.getElementById("compliance").value;
    const addSecurity = document.getElementById("addsecurity").value;

    let result = "";
    // Simple descison logic, that will be updated later.
    if (useCase === "transit" && addSecurity === "perfect") {
        result = "Recommendation: TLS 1.3 using ECDHE + AES-256-GCM.";
    }
    else if (sensitivity === "high" || threatLevel === "critical") {
        result = "Recommendation: Hybrid Encryption using AES-256 for data encryption and RSA-4096 or ECC for key exchange.";
    }
    else if (performance === "optimized" && dataVolume === "veryhigh") {
        result = "Recommendation: AES-128-GCM with hardware acceleration for high throughput environments.";
    }
    else {
        result = "Recommendation: Standard Hybrid Encryption (AES-256 + ECC key exchange).";
    }

    document.getElementById("resultBox").innerHTML =
        "<h3>Recommended Configuration</h3><p>" + result + "</p>";
});