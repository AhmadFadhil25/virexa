// =====================================================
// VIREXA
// Domain Threat Scanner
// =====================================================


// =====================================================
// ELEMENTS
// =====================================================

const apiKeyInput = document.getElementById("apiKey");

const proxyInput = document.getElementById("proxyUrl");

const thresholdInput = document.getElementById("threshold");

const delayInput = document.getElementById("delay");

const testDomainInput = document.getElementById("testDomain");

const testButton = document.getElementById("testButton");

const clearButton = document.getElementById("clearButton");

const systemStatus = document.getElementById("systemStatus");

const loading = document.getElementById("loading");

const errorBox = document.getElementById("errorBox");

const resultContent = document.getElementById("resultContent");


// =====================================================
// RESULT ELEMENTS
// =====================================================

const resultDomain =
    document.getElementById("resultDomain");

const resultStatus =
    document.getElementById("resultStatus");

const resultMalicious =
    document.getElementById("resultMalicious");

const resultSuspicious =
    document.getElementById("resultSuspicious");

const resultUndetected =
    document.getElementById("resultUndetected");

const resultTotal =
    document.getElementById("resultTotal");

const rawResponse =
    document.getElementById("rawResponse");


// =====================================================
// LOCAL STORAGE
// =====================================================

// Proxy disimpan karena bukan credential
const savedProxy =
    localStorage.getItem("virexa_proxy");

if (savedProxy) {
    proxyInput.value = savedProxy;
}


// API key juga dapat disimpan secara lokal
// sesuai desain Virexa.
//
// NOTE:
// API key tetap berada di browser pengguna.
// Jangan pernah hardcode API key ke GitHub.

const savedApiKey =
    localStorage.getItem("virexa_api_key");

if (savedApiKey) {
    apiKeyInput.value = savedApiKey;
}


// =====================================================
// SAVE CONFIG
// =====================================================

proxyInput.addEventListener("change", () => {

    localStorage.setItem(
        "virexa_proxy",
        proxyInput.value.trim()
    );

});


apiKeyInput.addEventListener("change", () => {

    const key = apiKeyInput.value.trim();

    if (key) {

        localStorage.setItem(
            "virexa_api_key",
            key
        );

    }

});


// =====================================================
// UTILITY
// =====================================================

function setSystemStatus(status) {

    systemStatus.textContent = status;

}


function showLoading() {

    loading.classList.remove("hidden");

    resultContent.classList.add("hidden");

    errorBox.classList.add("hidden");

}


function hideLoading() {

    loading.classList.add("hidden");

}


function showError(message) {

    errorBox.textContent = message;

    errorBox.classList.remove("hidden");

}


function clearError() {

    errorBox.textContent = "";

    errorBox.classList.add("hidden");

}


// =====================================================
// NORMALIZE DOMAIN
// =====================================================

function normalizeDomain(domain) {

    domain = domain.trim();

    domain = domain.replace(
        /^https?:\/\//i,
        ""
    );

    domain = domain.split("/")[0];

    domain = domain.split("?")[0];

    return domain;
}


// =====================================================
// CLASSIFY RESULT
// =====================================================

function classifyDomain(stats) {

    const malicious =
        stats.malicious || 0;

    const suspicious =
        stats.suspicious || 0;

    const total =
        Object.values(stats)
            .reduce(
                (sum, value) =>
                    sum + Number(value || 0),
                0
            );


    const threshold =
        Number(thresholdInput.value) || 2;


    /*
     * Logika awal:
     *
     * malicious >= threshold
     *       -> Malicious
     *
     * malicious > 0
     *       -> Phishing
     *
     * suspicious > 0
     *       -> Suspicious
     *
     * selain itu
     *       -> Bersih
     */


    if (malicious >= threshold) {

        return {
            name: "Malicious",
            className: "status-malicious"
        };

    }


    if (malicious > 0) {

        return {
            name: "Phishing",
            className: "status-phishing"
        };

    }


    if (suspicious > 0) {

        return {
            name: "Suspicious",
            className: "status-suspicious"
        };

    }


    return {
        name: "Bersih",
        className: "status-clean"
    };

}


// =====================================================
// DISPLAY RESULT
// =====================================================

function displayResult(domain, data) {

    const attributes =
        data?.data?.attributes || {};

    const stats =
        attributes.last_analysis_stats || {};


    const malicious =
        Number(stats.malicious || 0);

    const suspicious =
        Number(stats.suspicious || 0);

    const undetected =
        Number(stats.undetected || 0);


    const total =
        malicious +
        suspicious +
        undetected +
        Number(stats.harmless || 0) +
        Number(stats.timeout || 0);


    const classification =
        classifyDomain(stats);


    // DOMAIN
    resultDomain.textContent =
        domain;


    // STATUS
    resultStatus.textContent =
        classification.name;


    resultStatus.className =
        "status-badge " +
        classification.className;


    // STATISTICS
    resultMalicious.textContent =
        malicious;


    resultSuspicious.textContent =
        suspicious;


    resultUndetected.textContent =
        undetected;


    resultTotal.textContent =
        total;


    // RAW JSON
    rawResponse.textContent =
        JSON.stringify(
            data,
            null,
            2
        );


    resultContent.classList.remove(
        "hidden"
    );

}


// =====================================================
// TEST VIRUSTOTAL
// =====================================================

async function testVirusTotal() {

    clearError();

    const apiKey =
        apiKeyInput.value.trim();

    const proxy =
        proxyInput.value.trim();

    let domain =
        testDomainInput.value.trim();


    // ---------------------------------------------
    // VALIDATION
    // ---------------------------------------------

    if (!apiKey) {

        showError(
            "VT API Key belum diisi."
        );

        return;

    }


    if (!proxy) {

        showError(
            "Proxy URL belum diisi."
        );

        return;

    }


    if (!domain) {

        showError(
            "Domain belum diisi."
        );

        return;

    }


    domain =
        normalizeDomain(domain);


    // ---------------------------------------------
    // SAVE CONFIG
    // ---------------------------------------------

    localStorage.setItem(
        "virexa_api_key",
        apiKey
    );

    localStorage.setItem(
        "virexa_proxy",
        proxy
    );


    // ---------------------------------------------
    // UI
    // ---------------------------------------------

    testButton.disabled = true;

    testButton.textContent =
        "Memeriksa...";

    showLoading();

    setSystemStatus(
        "Scanning"
    );


    try {

        // -----------------------------------------
        // BUILD URL
        // -----------------------------------------

        const endpoint =
            `${proxy.replace(/\/$/, "")}/domain?domain=${encodeURIComponent(domain)}`;


        // -----------------------------------------
        // REQUEST TO CLOUDFLARE WORKER
        // -----------------------------------------

        const response =
            await fetch(
                endpoint,
                {
                    method: "GET",

                    headers: {
                        "X-API-Key": apiKey,

                        "Accept":
                            "application/json"
                    }
                }
            );


        // -----------------------------------------
        // READ RESPONSE
        // -----------------------------------------

        const data =
            await response.json();


        // -----------------------------------------
        // ERROR
        // -----------------------------------------

        if (!response.ok) {

            let message =
                data?.error ||
                `Request gagal (${response.status})`;

            throw new Error(message);

        }


        // -----------------------------------------
        // DISPLAY
        // -----------------------------------------

        displayResult(
            domain,
            data
        );


        setSystemStatus(
            "Connected"
        );


    } catch (error) {

        console.error(
            "Virexa Error:",
            error
        );


        showError(
            error.message ||
            "Terjadi kesalahan saat menghubungi proxy."
        );


        setSystemStatus(
            "Error"
        );

    } finally {

        hideLoading();

        testButton.disabled = false;

        testButton.textContent =
            "Test VirusTotal";

    }

}


// =====================================================
// CLEAR
// =====================================================

function clearResult() {

    testDomainInput.value = "";

    resultContent.classList.add(
        "hidden"
    );

    errorBox.classList.add(
        "hidden"
    );

    rawResponse.textContent = "";

    resultDomain.textContent = "-";

    resultStatus.textContent = "-";

    resultMalicious.textContent = "0";

    resultSuspicious.textContent = "0";

    resultUndetected.textContent = "0";

    resultTotal.textContent = "0";

    setSystemStatus("Idle");

}


// =====================================================
// EVENTS
// =====================================================

testButton.addEventListener(
    "click",
    testVirusTotal
);


clearButton.addEventListener(
    "click",
    clearResult
);


// ENTER = TEST
testDomainInput.addEventListener(
    "keydown",
    (event) => {

        if (event.key === "Enter") {

            testVirusTotal();

        }

    }
);
