
////////////////////////////////////////////////////////////////////////////////
// Encryption / Decryption Benchmark
////////////////////////////////////////////////////////////////////////////////

function randomBytes(size) {
    const data = new Uint8Array(size);

    const CHUNK = 65536;

    for (let offset = 0; offset < size; offset += CHUNK) {
        const length = Math.min(CHUNK, size - offset);

        crypto.getRandomValues(
            data.subarray(offset, offset + length)
        );
    }

    return data;
}

function mean(arr) {
    return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function sigma(arr, mu) {
    return Math.sqrt(
        arr.reduce((acc, x) => acc + Math.pow(x - mu, 2), 0) / arr.length
    );
}

function benchmarkEncryptDecryptForSize(
    sizeBytes,
    publicKey,
    secretKey,
    iterations = 100
) {
    const encTimes = [];
    const decTimes = [];

    const eci_core = new window.EicCrypt();
    const plaintext = randomBytes(sizeBytes);

    for (let i = 0; i < iterations; i++) {


        //------------------------------------------------------------------
        // Encryption
        //------------------------------------------------------------------
        const encResult =
            eci_core.encrypt_pdf(publicKey, plaintext);
        encTimes.push(encResult.time_ms);

        //------------------------------------------------------------------
        // Decryption
        //------------------------------------------------------------------
        const decResult =
            eci_core.decrypt_pdf(secretKey, encResult.ciphertext);

        decTimes.push(decResult.time_ms);
    }

    const muEnc = mean(encTimes);
    const muDec = mean(decTimes);

    return {
        sizeBytes,

        muEnc,
        sigmaEnc: sigma(encTimes, muEnc),

        muDec,
        sigmaDec: sigma(decTimes, muDec)
    };
}

////////////////////////////////////////////////////////////////////////////////
// Popup window
////////////////////////////////////////////////////////////////////////////////

let cryptoBenchWindow = null;
let cryptoBenchChart = null;

function openCryptoBenchmarkWindow() {

    cryptoBenchWindow =
        window.open(
            "",
            "CryptoBenchmark",
            "width=1100,height=800"
        );

    const doc = cryptoBenchWindow.document;

    doc.open();

    doc.write(`
        <html>
        <head>
            <title>Encryption / Decryption Benchmark</title>

            <style>

                body{
                    font-family:Arial;
                    margin:20px;
                }

                h2{
                    margin-bottom:10px;
                }

                table{
                    border-collapse:collapse;
                    width:100%;
                    margin-top:20px;
                }

                th,td{
                    border:1px solid #ccc;
                    padding:6px;
                    text-align:right;
                }

                th{
                    background:#f0f0f0;
                }

                tr:nth-child(even){
                    background:#fafafa;
                }

            </style>
        </head>

        <body>

            <h2>
                Encryption / Decryption Benchmark
            </h2>

            <div id="summary"></div>

            <canvas id="cryptoChart"></canvas>

            <div id="table-container"></div>

        </body>
        </html>
    `);

    doc.close();

    const script = doc.createElement("script");

    script.src =
        "https://cdn.jsdelivr.net/npm/chart.js";

    script.onload = () => {
        cryptoBenchWindow.__chartReady = true;
    };

    doc.head.appendChild(script);
}

////////////////////////////////////////////////////////////////////////////////
// Draw results
////////////////////////////////////////////////////////////////////////////////

function drawCryptoBenchmarkResults(results) {

    const wait = () => {

        const doc = cryptoBenchWindow.document;

        if (
            !cryptoBenchWindow.Chart ||
            !cryptoBenchWindow.__chartReady
        ) {
            setTimeout(wait, 100);
            return;
        }

        const labels =
            results.map(
                r => (r.sizeBytes / (1024 * 1024)).toFixed(2)
            );

        const enc =
            results.map(r => r.muEnc);

        const dec =
            results.map(r => r.muDec);

        if (cryptoBenchChart)
            cryptoBenchChart.destroy();

        cryptoBenchChart =
            new cryptoBenchWindow.Chart(
                doc.getElementById("cryptoChart"),
                {
                    type: "line",

                    data: {

                        labels,

                        datasets: [

                            {
                                label:
                                    "Encryption μ (ms)",

                                data: enc,

                                borderColor: "blue",

                                borderWidth: 2,

                                fill: false
                            },

                            {
                                label:
                                    "Decryption μ (ms)",

                                data: dec,

                                borderColor: "red",

                                borderWidth: 2,

                                fill: false
                            }
                        ]
                    },

                    options: {

                        responsive: true,

                        plugins: {

                            title: {

                                display: true,

                                text:
                                    "Execution Time vs Input Size"
                            }
                        },

                        scales: {

                            x: {

                                title: {

                                    display: true,

                                    text:
                                        "Input Size (MB)"
                                }
                            },

                            y: {

                                title: {

                                    display: true,

                                    text:
                                        "Time (ms)"
                                }
                            }
                        }
                    }
                }
            );

        //------------------------------------------------------------------
        // Table
        //------------------------------------------------------------------

        let html = `
        <h3>Detailed Results</h3>

        <table>

            <thead>

                <tr>

                    <th>Size (KB)</th>

                    <th>μ Enc (ms)</th>
                    <th>σ Enc (ms)</th>

                    <th>μ Dec (ms)</th>
                    <th>σ Dec (ms)</th>

                </tr>

            </thead>

            <tbody>
        `;

        results.forEach(r => {

            html += `
            <tr>

                <td>
                    ${(r.sizeBytes/1024).toFixed(0)}
                </td>

                <td>
                    ${r.muEnc.toFixed(4)}
                </td>

                <td>
                    ${r.sigmaEnc.toFixed(4)}
                </td>

                <td>
                    ${r.muDec.toFixed(4)}
                </td>

                <td>
                    ${r.sigmaDec.toFixed(4)}
                </td>

            </tr>
            `;
        });

        html += `
            </tbody>
        </table>
        `;

        doc.getElementById(
            "table-container"
        ).innerHTML = html;

        doc.getElementById(
            "summary"
        ).innerHTML =
            `<b>${results.length}</b> sizes tested,
             <b>100</b> experiments per size`;
    };

    wait();
}

////////////////////////////////////////////////////////////////////////////////
// Progress overlay
////////////////////////////////////////////////////////////////////////////////

function showCryptoBenchmarkProgress(
    current,
    total,
    sizeMB
) {

    let overlay =
        document.getElementById(
            "crypto-bench-overlay"
        );

    if (!overlay) {

        overlay =
            document.createElement("div");

        overlay.id =
            "crypto-bench-overlay";

        overlay.style.cssText = `
            position:fixed;
            inset:0;
            background:rgba(0,0,0,0.5);
            display:flex;
            align-items:center;
            justify-content:center;
            color:white;
            z-index:99999;
        `;

        document.body.appendChild(
            overlay
        );
    }

    const pct =
        Math.round(
            current * 100 / total
        );

    overlay.innerHTML = `
        <div style="
            background:#222;
            padding:30px;
            border-radius:10px;
            min-width:350px;
            text-align:center;
        ">

            <h3>
                Running Benchmark
            </h3>

            <p>
                Size:
                ${sizeMB.toFixed(2)} MB
            </p>

            <p>
                ${current}/${total}
            </p>

            <p>
                ${pct}% complete
            </p>

        </div>
    `;
}

function hideCryptoBenchmarkProgress() {

    const overlay =
        document.getElementById(
            "crypto-bench-overlay"
        );

    if (overlay)
        overlay.remove();
}

////////////////////////////////////////////////////////////////////////////////
// Main benchmark
////////////////////////////////////////////////////////////////////////////////

window.runEncryptionBenchmark = function () {

    // constant keys for testing
    const publicKey ="oMM3Jbr7Pr5kR1NG79cbU7zgCMS6vu3f1QbfeG7NhQwO";

    const secretKey ="ZAUDuGkMlQFA3rpy/cavlRtFSB1/iHW3jNlUDtPz3ek=";

    const sizes = [

        100 * 1024,
        250 * 1024,
        500 * 1024,

        1 * 1024 * 1024,
        2 * 1024 * 1024,
        4 * 1024 * 1024,
        6 * 1024 * 1024,
        8 * 1024 * 1024,
        10 * 1024 * 1024
    ];

    const results = [];

    function runNext(index) {

        if (index >= sizes.length) {

            hideCryptoBenchmarkProgress();

            if (
                !cryptoBenchWindow ||
                cryptoBenchWindow.closed
            ) {
                openCryptoBenchmarkWindow();
            }

            drawCryptoBenchmarkResults(
                results
            );

            return;
        }

        const size =
            sizes[index];

        showCryptoBenchmarkProgress(
            index + 1,
            sizes.length,
            size / (1024 * 1024)
        );

        setTimeout(() => {

            try {

                const r =
                    benchmarkEncryptDecryptForSize(
                        size,
                        publicKey,
                        secretKey,
                        100
                    );

                results.push(r);

                console.log(r);

            } catch (e) {

                hideCryptoBenchmarkProgress();

                alert(
                    "Benchmark failed: " +
                    e.message
                );

                return;
            }

            runNext(index + 1);

        }, 50);
    }

    runNext(0);
};