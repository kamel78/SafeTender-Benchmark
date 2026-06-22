import { dragStart, startResize, copyRowText, bringToFront, user_as_table,
         serialize_wShamir_list, deserialize_wShamir_list,send_share_to_autority,
         broadcast_sub_shares } from './core.js';


export function initializeTablesZIndex() 
    {
        document.querySelectorAll('.table-wrapper').forEach((table, index) => {
            table.style.zIndex = 10 + index; 
        });
    }

export async function loadWasm() {
        const { default: init, WShamirUser, PubKeyAdder, Combiner,EicCrypt } = await import("../pkg/wasm_interface.js");
        const wasmInstance = await init();
        const staticLinearMemoryBytes = wasmInstance.memory.buffer.byteLength;
        console.log(`Static Linear Memory: ${staticLinearMemoryBytes / 1024} KB`)
        window.WShamirUser = WShamirUser;
        window.PubKeyAdder = PubKeyAdder;
        window.Combiner = Combiner;
        window.EicCrypt = EicCrypt;
        window.highestZIndex = 10;
        document.dispatchEvent(new Event("wasmLoaded"));
    }

// Save page state to be loaded next 
export function save_share_conf() 
    {
        try {
            const container = document.getElementById('tableContainer'); 
            if (!container) {
                console.error("Container #tableContainer not found!");
                return;
            }
            const serializedHTML = container.innerHTML;
            let serialized_data = serialize_wShamir_list();
            const globalState = {
                users_list: users_list,
                wShamir_list: serialized_data, 
                global_threshold: global_threshold,
                global_count: global_count,
                shares_count :shares_count
            };
            localStorage.setItem('serializedHTML', serializedHTML);
            localStorage.setItem('globalState', JSON.stringify(globalState));
        } catch (error) {
            console.error('Error saving state:', error);
        }
    }

// Restore page state when reloaded
export function restore_share_conf() 
    {
        try {          
            const savedHTML = localStorage.getItem('serializedHTML');
            const container = document.getElementById('tableContainer');
            if (container && savedHTML) {
                container.innerHTML = savedHTML; 
            } else if (!container) {
                console.error("Container #tableContainer not found!");
            }
            const savedGlobalState = localStorage.getItem('globalState');
            if (savedGlobalState) {
                const state = JSON.parse(savedGlobalState);
                if (state.global_count >0) {
                            wShamir_list = deserialize_wShamir_list(state.wShamir_list);
                            users_list = state.users_list;
                            global_threshold = state.global_threshold;
                            global_count = state.global_count;
                            shares_count = state.shares_count;
                            let tables = document.querySelectorAll("table");
                            tables.forEach(table => {                                  
                                    if (table.tBodies[0].rows[0].cells[0].innerHTML.indexOf("Authority")>-1) 
                                            {   rec_table = table;}
                                });
                            const tableWrappers = document.getElementsByClassName('table-wrapper');
                            Array.from(tableWrappers).forEach(wrapper => {
                                wrapper.addEventListener('mousedown', dragStart);
                                wrapper.addEventListener("mousedown", function() {
                                            bringToFront(wrapper);
                                        });
                                });
                            const tableResizer = document.getElementsByClassName('resizer');
                            Array.from(tableResizer).forEach(resizer => {
                                resizer.addEventListener('mousedown', startResize);
                                });
                            const tableBtnsend = document.getElementsByClassName('send-btn');
                            Array.from(tableBtnsend).forEach(btn => {
                                btn.onclick = function() { broadcast_sub_shares(btn.getAttribute("username"), btn); };
                                }); 
                            document.getElementById('save-button').disabled = false;   
                            let allSent = Array.from(document.querySelectorAll(".send-btn"))
                                               .every(button => button.classList.contains('sent'));            
                            document.getElementById('rec-button').disabled = !allSent;
                            document.getElementById('enc-button').disabled = false;   
                            document.getElementById('userCount').value = global_count;   
                            document.getElementById('threshold').value = global_threshold;   
                            let copybtn = document.getElementById('copy-btn');   
                            copybtn.addEventListener("click", () => {
                                let pkey =rec_table.tBodies[0].rows[rec_table.tBodies[0].rows.length-1].textContent.split(':').slice(1).join(':').trim();
                                copyRowText(pkey)});
                            console.log('enabled') ;
                            }       
            }
        } catch (error) {
            console.error('Error restoring state:', error);
        }
    }

function benchmark_generate_secret(iterations = 50) {
    const times = [];
    const users = Array.from(wShamir_list.values());
    for (let i = 0; i < iterations; i++) {

        for (let u of users) {
            const t0 = performance.now();
            u.generate_secret();
            const t1 = performance.now();

            times.push(t1 - t0); // per-call timing
        }
    }
    // mean (μ)
    const mu = times.reduce((a, b) => a + b, 0) / times.length;
    // variance
    const variance = times.reduce((acc, t) =>
        acc + Math.pow(t - mu, 2), 0) / times.length;
    const sigma = Math.sqrt(variance);
    console.log({ mu, sigma, variance });
    document.getElementById("bench-result").innerHTML = `
        μ (per call): ${mu.toFixed(4)} ms <br>
        σ: ${sigma.toFixed(4)} ms <br>
        samples: ${times.length}
    `;
}

export function generate_users_conf() {
    const container = document.getElementById("tableContainer");
    container.innerHTML = "";
    let userCount = parseInt(document.getElementById("userCount").value) || 3;
    let threshold = parseInt(document.getElementById("threshold").value) || 0;

    (async () => {
        try {
            const { default: init, WShamirUser, PubKeyAdder, Combiner, EicCrypt } = await import("../pkg/wasm_interface.js");
            const dkgInstance = await init(); 
            
            users_list = [];
            wShamir_list.clear();
            global_count = userCount;
            global_threshold = threshold;
            let radius = 35;            
            
            // 1. Render UI elements first (keeps DOM allocation out of crypto benchmark)
            for (let i = 0; i < userCount; i++) {
                let angle = (i / userCount) * (2 * Math.PI);
                const newname = 'User ' + (i + 1);
                users_list.push(newname);
                container.appendChild(user_as_table(newname, angle, radius, i));
            }

            // ==========================================
            // START BENCHMARK SAMPLING
            // ==========================================
            if (window.gc) window.gc(); // Clear stale memory if flag is enabled
            
            const jsHeapBaseline = performance.memory.usedJSHeapSize;
            const wmemBaseline = dkgInstance.memory.buffer.byteLength;

            // 2. Execute the actual DKG cryptographic setup loop
            users_list.forEach(uname => {
                wShamir_list.set(uname, new WShamirUser(users_list, uname, global_threshold));
                wShamir_list.get(uname).generate_secret();
            });

            if (window.gc) window.gc(); // Clear transient garbage before final reading
            
            const jsHeapPost = performance.memory.usedJSHeapSize;
            const peakDkgBytes = dkgInstance.memory.buffer.byteLength;
            // ==========================================
            // END BENCHMARK SAMPLING
            // ==========================================

            // Compute Deltas
            const wmemGrowth = peakDkgBytes - wmemBaseline;
            const totalJsHeapGrowth = jsHeapPost - jsHeapBaseline;
            
            // Isolate JS Glue Overhead
            const jsHeapOverheadBytes = Math.max(0, totalJsHeapGrowth - wmemGrowth);

            // Log Metrics
            console.log(`Wasm initialized successfully.`);
            console.log(`Peak DKG Linear Memory: ${(peakDkgBytes / (1024 * 1024)).toFixed(4)} MB`);
            console.log(`JS Heap Overhead (wasm-bindgen glue): ${(jsHeapOverheadBytes / 1024).toFixed(1)} KB`);

        } catch (error) {
            console.error("Failed to initialize Wasm or run benchmark:", error);
        }
    })();
}
// export function generate_users_conf() 
//     {
//         const container = document.getElementById("tableContainer");
//         container.innerHTML = "";
//         let userCount = parseInt(document.getElementById("userCount").value) || 3;
//         let threshold = parseInt(document.getElementById("threshold").value) || 0;

        
// (async () => {
//     try {
//         // 1. Now 'await' is inside an async context, which is perfectly valid
//                 const { default: init, WShamirUser, PubKeyAdder, Combiner,EicCrypt } = await import("../pkg/wasm_interface.js");

//         const dkgInstance = await init(); 
//          users_list = [];
//         wShamir_list.clear();
//         global_count = userCount;
//         global_threshold = threshold;
//         let radius = 35;            
//         for (let i = 0; i < userCount; i++) {
//             let angle = (i / userCount) * (2 * Math.PI);
//             const newname = 'User ' + (i + 1);
//             users_list.push(newname);
//             container.appendChild(user_as_table(newname, angle, radius, i));
//         }
//         users_list.forEach (uname => {
//             wShamir_list.set(uname,new WShamirUser(users_list,uname,global_threshold));
//             wShamir_list.get(uname).generate_secret();
//         })
//         const peakDkgBytes = dkgInstance.memory.buffer.byteLength;
//         console.log(`Peak DKG Linear Memory: ${peakDkgBytes / (1024 * 1024)} MB`);
//         // 2. Execute your benchmarking logic here
//         console.log("Wasm initialized successfully.");
//     } catch (error) {
//         console.error("Failed to initialize Wasm:", error);
//     }
// })();
       
//     }

let benchWindow = null;
let muChartInstance = null;

function generate_users_conf_for_benchmark(userCount, benchThreshold) {

    // Work on local variables only, never touch globals
    const local_users_list = [];
    const local_wShamir_list = new Map();

    for (let i = 0; i < userCount; i++) {
        local_users_list.push('User ' + (i + 1));
    }

    local_users_list.forEach(uname => {
        local_wShamir_list.set(uname, new WShamirUser(local_users_list, uname, benchThreshold));
        local_wShamir_list.get(uname).generate_secret();
    });

    return local_wShamir_list;
}

function benchmark_for_n(n, benchThreshold, iterations = 50) {

    const local_wShamir_list = generate_users_conf_for_benchmark(n, benchThreshold);
    const users = Array.from(local_wShamir_list.values());

    const times_total = [];
    const times_wasm  = [];

    for (let i = 0; i < iterations; i++) {
        const t0 = performance.now();
        for (let u of users) {
            u.generate_secret();
        }
        const t1 = performance.now();

        times_total.push(t1 - t0);

        // ✅ Sum internal WASM timings across all users for this iteration
        const wasm_time = users.reduce((acc, u) => acc + u.get_last_timing_ms(), 0);
        times_wasm.push(wasm_time);
    }

    return compute_stats(n, times_total, times_wasm);
}

function openBenchmarkWindow() {

    benchWindow = window.open("", "BenchmarkResults", "width=900,height=700");

    const doc = benchWindow.document;

    // build page normally (NO scripts)
    doc.open();
   doc.write(`
    <html>
    <head>
        <title>Benchmark Results</title>
        <style>
            body { font-family: Arial; margin: 20px; }
            canvas { margin-top: 20px; }
            table thead th { background-color: #f0f0f0; }
            table tbody tr:nth-child(even) { background-color: #fafafa; }
            table tbody tr:hover { background-color: #eef4ff; }
        </style>
    </head>
    <body>
        <h2>Benchmark Results</h2>
        <div id="bench-result"></div>
        <canvas id="muChart"></canvas>
        <div id="bench-table"></div>   <!-- ✅ added -->
    </body>
    </html>
`);
    doc.close();

    // ✅ SAFE script injection (no document.write)
    const script = doc.createElement("script");
    script.src = "https://cdn.jsdelivr.net/npm/chart.js";

    script.onload = () => {
        benchWindow.__chartReady = true;
    };

    doc.head.appendChild(script);
}

function draw_graphs_in_window(results) {
    const wait = () => {
        const doc = benchWindow.document;
        if (!benchWindow.Chart || !benchWindow.__chartReady ||
            !doc.getElementById("muChart") )
            {
            setTimeout(wait, 50);
            return;
        }

        doc.getElementById("bench-result").innerHTML =
            `<b>Benchmark completed</b><br>samples: ${results.length}`;

        const ns             = results.map(r => r.n);
        const mus_total      = results.map(r => r.mu_total);
        const mus_wasm       = results.map(r => r.mu_wasm);
        const mus_boundary   = results.map(r => r.mu_boundary);
        const sigs_total     = results.map(r => r.sigma_total);
        const sigs_wasm      = results.map(r => r.sigma_wasm);
        const sigs_boundary  = results.map(r => r.sigma_boundary);

        if (muChartInstance)    muChartInstance.destroy();

        muChartInstance = new benchWindow.Chart(doc.getElementById("muChart"), {
            type: "line",
            data: {
                labels: ns,
                datasets: [
                    { label: "μ total (ms)",    data: mus_total,    borderColor: "blue",  borderWidth: 2, fill: false },
                    { label: "μ WASM (ms)",     data: mus_wasm,     borderColor: "green", borderWidth: 2, fill: false },
                    { label: "μ boundary (ms)", data: mus_boundary, borderColor: "orange",borderWidth: 2, fill: false }
                ]
            },
            options: { responsive: true }
        });

        const tableHTML = `
            <h3>Detailed Results</h3>
            <table border="1" cellpadding="6" cellspacing="0"
                   style="border-collapse:collapse; width:100%; margin-top:16px; font-family:Arial; font-size:0.9em;">
                <thead style="background:#f0f0f0;">
                    <tr>
                        <th>n</th>
                        <th>μ total</th><th>σ total</th>
                        <th>μ WASM</th><th>σ WASM</th>
                        <th>μ boundary</th><th>σ boundary</th>
                    </tr>
                </thead>
                <tbody>
                    ${results.map(r => `
                        <tr>
                            <td style="text-align:center">${r.n}</td>
                            <td style="text-align:right">${r.mu_total.toFixed(4)}</td>
                            <td style="text-align:right">${r.sigma_total.toFixed(4)}</td>
                            <td style="text-align:right">${r.mu_wasm.toFixed(4)}</td>
                            <td style="text-align:right">${r.sigma_wasm.toFixed(4)}</td>
                            <td style="text-align:right">${r.mu_boundary.toFixed(4)}</td>
                            <td style="text-align:right">${r.sigma_boundary.toFixed(4)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        doc.getElementById("bench-table").innerHTML = tableHTML;
    };
    wait();
}

function generate_users_conf_for_time(userCount) {
    users_list = [];
    wShamir_list.clear();
    const rawThreshold = parseInt(document.getElementById("threshold").value) || 0;
    global_count = userCount;
    global_threshold = Math.max(1, Math.floor(userCount / 2));
    for (let i = 0; i < userCount; i++) {
        users_list.push('User ' + (i + 1));
    }
    users_list.forEach(uname => {
        wShamir_list.set(uname, new WShamirUser(users_list, uname, global_threshold));
        wShamir_list.get(uname).generate_secret();
    });
}

function benchmark_for_n_time(n, iterations = 50) {
    generate_users_conf_for_time(n); 
    const users = Array.from(wShamir_list.values());
    const times = [];
    for (let i = 0; i < iterations; i++) {
        const t0 = performance.now();

        for (let u of users) {
            u.generate_secret(); 
        }
        const t1 = performance.now();
        times.push((t1 - t0) / users.length); // average time per user
    }
    const mu = times.reduce((a, b) => a + b, 0) / times.length;
    const variance = times.reduce((acc, t) => acc + Math.pow(t - mu, 2), 0) / times.length;
    const sigma = Math.sqrt(variance);
    return { n, mu, sigma };
}


function showBenchmarkProgress(current, total, n) {
    let overlay = document.getElementById("bench-overlay");
    if (!overlay) {
        overlay = document.createElement("div");
        overlay.id = "bench-overlay";
        overlay.style.cssText = `
            position: fixed; inset: 0;
            background: rgba(0,0,0,0.5);
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            z-index: 9999; color: white; font-family: Arial;
        `;
        document.body.appendChild(overlay);
    }

    const pct = Math.round((current / total) * 100);

    overlay.innerHTML = `
        <div style="
            background: #1e1e2e; border-radius: 12px;
            padding: 32px 48px; text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            min-width: 320px;
        ">
            <div style="font-size: 1.3em; font-weight: bold; margin-bottom: 8px;">
                🔬 Running Benchmark
            </div>
            <div style="color: #aaa; margin-bottom: 20px; font-size: 0.95em;">
                Testing n = <b style="color:white">${n}</b> users
                &nbsp;(${current} / ${total})
            </div>
            <div style="
                background: #333; border-radius: 999px;
                height: 10px; width: 100%; overflow: hidden;
            ">
                <div style="
                    background: linear-gradient(90deg, #4f8ef7, #a78bfa);
                    height: 100%; width: ${pct}%;
                    border-radius: 999px;
                    transition: width 0.2s ease;
                "></div>
            </div>
            <div style="margin-top: 12px; color: #aaa; font-size: 0.85em;">
                ${pct}% complete
            </div>
        </div>
    `;
}

function hideBenchmarkProgress() {
    const overlay = document.getElementById("bench-overlay");
    if (overlay) overlay.remove();
}



window.runBenchmarkAll = function () {
    const ns = [3, 5, 10, 15, 20, 30, 50];
    const results = [];
    function runNext(index) {
        if (index >= ns.length) {
            hideBenchmarkProgress();

            if (!benchWindow || benchWindow.closed) {
                openBenchmarkWindow();
            }
            draw_graphs_in_window(results);
            return;
        }

        const n = ns[index];
        showBenchmarkProgress(index, ns.length, n);
        setTimeout(() => {
            try {
                const select = document.getElementById("benchmark-threshold");
                let pos = select.selectedIndex;
                let benchThreshold =0;
                if (pos === 0) { benchThreshold = Math.max(1, Math.floor(n / 2));}
                else if (pos === 1) { benchThreshold = Math.max(1, Math.floor(2*n / 3));}
                else if (pos === 2) { benchThreshold = Math.max(1, Math.floor(n));}
                //  const benchThreshold = Math.max(1, Math.floor(2*n / 3));
                const r = benchmark_for_n(n, benchThreshold);
                results.push(r);
                console.log(r);
            } catch (e) {
                hideBenchmarkProgress();
                console.error("Benchmark failed:", e);
                alert("Benchmark error: " + e.message);
                return;
            }
            runNext(index + 1);
        }, 30);
    }

    runNext(0);
};

window.runBenchmark = function () {
    const n = parseInt(document.getElementById("userCount").value) || 3;
    const result = benchmark_for_n_time(n, 50);
    console.log(result);
    document.getElementById("bench-result").innerHTML = `
        n = ${result.n} <br>
        μ = ${result.mu.toFixed(4)} ms <br>
        σ = ${result.sigma.toFixed(4)} ms
    `;
};

export function reset_share_conf()
    {
        document.querySelectorAll('.table-wrapper').forEach(wrapper => wrapper.remove());
        document.getElementById('save-button').disabled = true;
        document.getElementById('rec-button').disabled = true;
        document.getElementById('enc-button').disabled = true;
        users_list = [];
        wShamir_list = new Map();
        global_threshold =0;
        global_count =0;
        shares_count = 0;
        save_share_conf();
    }

// Load created shares for reconstruction    
export function load_shares_for_reconstruction() 
    {
        try {          
            const savedHTML = localStorage.getItem('serializedHTML');
            const container = document.getElementById('tableContainer');
            const savedGlobalState = localStorage.getItem('globalState');
            if (savedGlobalState) {                
                const state = JSON.parse(savedGlobalState);
                if (state.shares_count == 0) {return}
            }
            else {return}
            if (container && savedHTML) {
                container.innerHTML = savedHTML; 
            } else if (!container) {
                console.error("Container #tableContainer not found!");
            }
            const state = JSON.parse(savedGlobalState);
            if (state.global_count >0) {
                        wShamir_list = deserialize_wShamir_list(state.wShamir_list);
                        users_list = state.users_list;
                        global_threshold = state.global_threshold;
                        global_count = state.global_count;

                        const tableWrappers = document.getElementsByClassName('table-wrapper');
                        Array.from(tableWrappers).forEach(wrapper => {
                            wrapper.addEventListener('mousedown', dragStart);
                            wrapper.addEventListener("mousedown", function() {
                                        bringToFront(wrapper);
                                    });
                            });
                        let tables = document.querySelectorAll("table");
                        tables.forEach(table => {
                                let num_lines = table.tBodies[0].rows.length;    
                                for (let i = 0; i<num_lines-3; i++) {table.tBodies[0].deleteRow(1)}
                                if (table.tBodies[0].rows[0].cells[0].innerHTML.indexOf("Authority")>-1) 
                                        {   table.tBodies[0].deleteRow(1);
                                            table.tBodies[0].rows[0].cells[0].textContent = "Authority of Reconstruction ";
                                            let KeyCell = table.querySelector("tr:last-child td");
                                            KeyCell.childNodes[0].nodeValue = "Secret Key :    ";
                                            let copyButton = table.querySelector("tr:last-child td button");                                            
                                            copyButton.addEventListener("click", () => {
                                                                            let key = KeyCell.childNodes[0].nodeValue.split(" : ").slice(1).join(" : ");
                                                                            copyRowText(key)}
                                                                       );
                                            auth_table = table;
                                        }
                            });

                        const tableResizer = document.getElementsByClassName('resizer');
                        Array.from(tableResizer).forEach(resizer => {
                            resizer.addEventListener('mousedown', startResize);
                            });
                        const tableBtnsend = document.getElementsByClassName('sent');
                        Array.from(tableBtnsend).forEach(btn => {                                
                            btn.classList.add('send-btn');                    
                            btn.classList.remove('sent');                    
                            btn.textContent ="Envoie";            
                            btn.disabled = false;
                            btn.onclick = function() { send_share_to_autority(btn.getAttribute("username"), btn); };
                            }); 
                        document.getElementById('rec-button').disabled = false;
                        document.getElementById('enc-button').disabled = false;   
                        document.getElementById('userCount').value = global_count;   
                        document.getElementById('threshold').value = global_threshold;                           
                        console.log('enabled') ;
                }
        } catch (error) {
            console.error('Error restoring state:', error);
        }
    }

// export function random_reconstruction()
//     {
//         load_shares_for_reconstruction();
//         let keys = Array.from(wShamir_list.keys()); 
//         let shuffled = keys.sort(() => Math.random() - 0.5); 
//         let selectedKeys = shuffled.slice(0, global_threshold);     
//         let selected_users = selectedKeys.map(key => [key, wShamir_list.get(key)]);
//         let btns = document.querySelectorAll(".send-btn");
//      (async () => {

//         try {
//         const { default: init, WShamirUser, PubKeyAdder, Combiner,EicCrypt } = await import("../pkg/wasm_interface.js");
//         const recInstance = await init();
        
//         btns.forEach(btn =>{
//                 let user = btn.getAttribute("username");
//                 if (selected_users.find(([key, _]) => key === user)) { send_share_to_autority(user,btn)}
//                 });
//         let selected_shares = selectedKeys.map(key => [key, wShamir_list.get(key).get_share()]);
//         let acombiner = new Combiner (users_list,global_threshold);
//         let secret_key = acombiner.combine_shares(selected_shares);

//         const peakRecBytes = recInstance.memory.buffer.byteLength;
//         console.log(`Peak Reconstruction Linear Memory: ${peakRecBytes / 1024} KB`);
//         let KeyCell = auth_table.querySelector("tr:last-child td");
//         KeyCell.childNodes[0].nodeValue = "Secrete Key : "+secret_key;
//     } catch (error) {
//         console.error("Failed to initialize Wasm:", error);
//     }
//     })();
       
        
//     }

export function random_reconstruction() {
    load_shares_for_reconstruction();
    let keys = Array.from(wShamir_list.keys()); 
    let shuffled = keys.sort(() => Math.random() - 0.5); 
    let selectedKeys = shuffled.slice(0, global_threshold);     
    let selected_users = selectedKeys.map(key => [key, wShamir_list.get(key)]);
    let btns = document.querySelectorAll(".send-btn");

    (async () => {
        try {
            const { default: init, WShamirUser, PubKeyAdder, Combiner, EicCrypt } = await import("../pkg/wasm_interface.js");
            const recInstance = await init();
            
            // 1. DOM update: visual trigger for button elements (kept outside benchmark)
            btns.forEach(btn => {
                let user = btn.getAttribute("username");
                if (selected_users.find(([key, _]) => key === user)) { 
                    send_share_to_autority(user, btn); 
                }
            });

            // ==========================================
            // START RECONSTRUCTION BENCHMARK SAMPLING
            // ==========================================
            if (window.gc) window.gc(); // Flush stale memory if GC is exposed

            const jsHeapBaseline = performance.memory.usedJSHeapSize;
            const wmemBaseline = recInstance.memory.buffer.byteLength;

            // 2. Core Cryptographic Execution Phase
            let selected_shares = selectedKeys.map(key => [key, wShamir_list.get(key).get_share()]);
            let acombiner = new Combiner(users_list, global_threshold);
            let secret_key = acombiner.combine_shares(selected_shares);

            if (window.gc) window.gc(); // Clean up intermediate marshalling garbage
            
            const jsHeapPost = performance.memory.usedJSHeapSize;
            const peakRecBytes = recInstance.memory.buffer.byteLength;
            // ==========================================
            // END RECONSTRUCTION BENCHMARK SAMPLING
            // ==========================================

            // Calculate Deltas
            const wmemGrowth = peakRecBytes - wmemBaseline;
            const totalJsHeapGrowth = jsHeapPost - jsHeapBaseline;
            
            // Isolate JS Glue Overhead for Reconstruction
            const jsHeapOverheadBytes = Math.max(0, totalJsHeapGrowth - wmemGrowth);

            // Print Metrics to Console
            console.log(`--- Reconstruction Memory Evaluation ---`);
            console.log(`Peak Reconstruction Linear Memory: ${(peakRecBytes / 1024).toFixed(1)} KB`);
            console.log(`JS Heap Overhead (wasm-bindgen glue): ${(jsHeapOverheadBytes / 1024).toFixed(1)} KB`);

            // 3. UI Update: Render the final derived secret key (kept outside benchmark)
            let KeyCell = auth_table.querySelector("tr:last-child td");
            KeyCell.childNodes[0].nodeValue = "Secret Key : " + secret_key;

        } catch (error) {
            console.error("Failed to run Reconstruction benchmark:", error);
        }
    })();
}

function generate_combine_data_for_benchmark(userCount, benchThreshold) {
    const local_users_list = [];
    const local_wShamir_list = new Map();
    for (let i = 0; i < userCount; i++) {
        local_users_list.push('User ' + (i + 1));
    }
    local_users_list.forEach(uname => {
        local_wShamir_list.set(uname, new WShamirUser(local_users_list, uname, benchThreshold));
        local_wShamir_list.get(uname).generate_secret();
    });
    local_users_list.forEach(uname => {
        const sender = local_wShamir_list.get(uname);
        local_users_list.forEach(other => {
            if (other !== uname) {
                const part = sender.get_secret_part_for_user(other);
                local_wShamir_list.get(other).update_share(uname, part);
            }
        });
    });
    const shuffled = [...local_users_list].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, benchThreshold);
    const selected_shares = selected.map(key => [key, local_wShamir_list.get(key).get_share()]);
    return { local_users_list, selected_shares };
}

function benchmark_combine_for_n(n, benchThreshold, iterations = 50) {
    const { local_users_list, selected_shares } = generate_combine_data_for_benchmark(n, benchThreshold);
    const times_total = [];
    const times_wasm  = [];
    for (let i = 0; i < iterations; i++) {
        const combiner = new Combiner(local_users_list, benchThreshold);
        const t0 = performance.now();
        combiner.combine_shares(selected_shares);
        const t1 = performance.now();
        times_total.push(t1 - t0);
        times_wasm.push(combiner.get_last_timing_ms());   // ✅
    }
    return compute_stats(n, times_total, times_wasm);
}

function compute_stats(n, times_total, times_wasm) {
    const mean = arr => arr.reduce((a, b) => a + b, 0) / arr.length;
    const sigma = (arr, mu) => Math.sqrt(
        arr.reduce((acc, t) => acc + Math.pow(t - mu, 2), 0) / arr.length
    );
    const mu_total    = mean(times_total);
    const mu_wasm     = mean(times_wasm);
    const mu_boundary = mu_total - mu_wasm;
    return {
        n,
        mu_total,    sigma_total:    sigma(times_total, mu_total),
        mu_wasm,     sigma_wasm:     sigma(times_wasm,  mu_wasm),
        mu_boundary, sigma_boundary: sigma(
            times_total.map((t, i) => t - times_wasm[i]),
            mu_boundary
        )
    };
}

window.runBenchmarkCombine = function () {
    const ns = [3, 5, 10, 15, 20, 30, 50];  
    const results = [];
    function runNext(index) {
        if (index >= ns.length) {
            hideBenchmarkProgress();
            if (!benchWindow || benchWindow.closed) {
                openBenchmarkWindow();
            }
            draw_graphs_in_window(results);
            return;
        }
        const n = ns[index];
        showBenchmarkProgress(index, ns.length, n);
        setTimeout(() => {
            try {
                const select = document.getElementById("benchmark-threshold");
                let pos = select.selectedIndex;
                let benchThreshold =0;
                if (pos === 0) { benchThreshold = Math.max(1, Math.floor(n / 2));}
                else if (pos === 1) { benchThreshold = Math.max(1, Math.floor(2*n/ 3));}
                else if (pos === 2) { benchThreshold = Math.max(1, Math.floor(n));}
                const r = benchmark_combine_for_n(n, benchThreshold);
                results.push(r);
                console.log(r);
            } catch (e) {
                hideBenchmarkProgress();
                console.error("Benchmark (combine_shares) failed:", e);
                alert("Benchmark error: " + e.message);
                return;
            }
            runNext(index + 1);
        }, 30);
    }
    runNext(0);
};


window.initializeTablesZIndex = initializeTablesZIndex;
window.loadWasm = loadWasm;
window.save_share_conf = save_share_conf;
window.restore_share_conf = restore_share_conf;
window.reset_share_conf = reset_share_conf;
window.generate_users_conf = generate_users_conf;
window.load_shares_for_reconstruction = load_shares_for_reconstruction;
window.random_reconstruction = random_reconstruction;

