namespace SecRev.Services;

internal static class ApiWebPage
{
    public const string Html = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecRev Text Analysis</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #1b1b1b; }
  textarea { width: 100%; height: 12rem; box-sizing: border-box; font: inherit; padding: .5rem; }
  button { margin-top: .75rem; padding: .5rem 1.25rem; font: inherit; cursor: pointer; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; }
  dt { font-weight: 600; }
  dd { margin: 0; }
  .error { color: #b00020; }
  .note { color: #555; font-size: .875rem; }
</style>
</head>
<body>
<h1>SecRev Text Analysis</h1>
<p class="note">Experimental demo. Text is sent to this service for analysis and is not stored or logged.</p>
<textarea id="text" placeholder="Paste text to analyze" maxlength="1000000"></textarea>
<button id="go">Analyze</button>
<p id="status" role="status"></p>
<dl id="result" hidden>
  <dt>Words</dt><dd id="words"></dd>
  <dt>Email candidates</dt><dd id="emails"></dd>
  <dt>Number groups</dt><dd id="numbers"></dd>
  <dt>Scan findings</dt><dd id="findings"></dd>
</dl>
<script>
const $ = id => document.getElementById(id);
$("go").addEventListener("click", async () => {
  const status = $("status"), result = $("result");
  status.className = ""; status.textContent = "Analyzing…"; result.hidden = true;
  try {
    const r = await fetch("/process", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: $("text").value })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || data.title || "Request failed (" + r.status + ")");
    $("words").textContent = data.analysis.words;
    $("emails").textContent = data.analysis.emailCandidates;
    $("numbers").textContent = data.analysis.numberGroups;
    $("findings").textContent = data.scan.findingCount === 0 ? "None" : data.scan.findings.join(", ");
    result.hidden = false; status.textContent = "";
  } catch (e) {
    status.className = "error"; status.textContent = e.message;
  }
});
</script>
</body>
</html>
""";
}
