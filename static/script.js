const $ = (id) => document.getElementById(id);
document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(item => item.classList.toggle("active", item === button));
  document.querySelectorAll(".panel").forEach(panel => panel.classList.toggle("active", panel.id === button.dataset.panel));
}));
async function postJSON(url, body) {
  const response = await fetch(url, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed.");
  return data;
}
function showError(target, message) {
  target.classList.remove("hidden");
  target.innerHTML = `<p>${escapeHTML(message)}</p>`;
}
function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
}
function riskClass(risk) {
  return risk === "High" ? "high" : risk === "Caution" ? "caution" : "lower";
}
$("urlForm").addEventListener("submit", async event => {
  event.preventDefault();
  const box = $("urlResult"); box.classList.remove("hidden"); box.innerHTML = "<p>Analyzing…</p>";
  try {
    const data = await postJSON("/api/url", {url:$("urlInput").value});
    box.innerHTML = `<h3>URL assessment</h3><p><strong>URL:</strong> ${escapeHTML(data.url)}</p><span class="risk ${riskClass(data.risk)}">${escapeHTML(data.risk)}</span><ul>${data.flags.map(flag=>`<li>${escapeHTML(flag)}</li>`).join("")}</ul><p>Reminder: heuristic only. A lower apparent risk does not guarantee safety.</p>`;
  } catch (error) { showError(box, error.message); }
});
$("togglePassword").addEventListener("click", () => {
  const input = $("passwordInput"); input.type = input.type === "password" ? "text" : "password";
  $("togglePassword").textContent = input.type === "password" ? "Show" : "Hide";
});
$("passwordForm").addEventListener("submit", async event => {
  event.preventDefault();
  const box = $("passwordResult"); box.classList.remove("hidden"); box.innerHTML = "<p>Checking composition…</p>";
  try {
    const data = await postJSON("/api/password", {password:$("passwordInput").value});
    const cls = data.label.toLowerCase();
    box.innerHTML = `<h3>Password composition</h3><span class="risk ${cls}">${escapeHTML(data.label)}</span><ul>${data.feedback.map(item=>`<li>${escapeHTML(item)}</li>`).join("")}</ul><p>Use a test password only. This check does not query breach databases.</p>`;
    $("passwordInput").value = "";
  } catch (error) { showError(box, error.message); }
});
$("datasetForm").addEventListener("submit", async event => {
  event.preventDefault();
  const box = $("datasetResult"); box.classList.remove("hidden"); box.innerHTML = "<p>Reviewing CSV…</p>";
  try {
    const form = new FormData(); form.append("file", $("csvInput").files[0]);
    const response = await fetch("/api/dataset", {method:"POST", body:form});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not review file.");
    if (!data.results.length) { box.innerHTML = "<p>No data rows found.</p>"; return; }
    box.innerHTML = `<h3>Dataset results (${data.results.length} rows)</h3><div style="overflow-x:auto"><table><thead><tr><th>Label</th><th>URL</th><th>Assessment</th><th>Warning signs</th></tr></thead><tbody>${data.results.map(item=>`<tr><td>${escapeHTML(item.example_label)}</td><td>${escapeHTML(item.url)}</td><td><span class="risk ${riskClass(item.risk)}">${escapeHTML(item.risk)}</span></td><td>${item.flags.map(escapeHTML).join("<br>")}</td></tr>`).join("")}</tbody></table></div>`;
  } catch (error) { showError(box, error.message); }
});
