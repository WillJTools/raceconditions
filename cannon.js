document.addEventListener("DOMContentLoaded", () => {
  const convertBtn = document.getElementById("convertButton");
  const copyBtn = document.getElementById("copyButton");
  const input = document.getElementById("webRequest");
  const output = document.getElementById("pythonScript");
  const concurrencyEl = document.getElementById("concurrency");
  const roundsEl = document.getElementById("rounds");
  const timeoutEl = document.getElementById("timeout");

  if (!convertBtn || !copyBtn || !input || !output || !concurrencyEl || !roundsEl || !timeoutEl) {
    console.error("Missing required UI elements.");
    return;
  }

  // Mild sanitization: same spirit as your REQ2PY front-end safety checks :contentReference[oaicite:3]{index=3}
  function sanitize(s) {
    return (s || "")
      .replace(/<script.*?>.*?<\/script>/gis, "")
      .replace(/javascript:/gi, "")
      .replace(/on\w+=["'].*?["']/gi, "");
  }

  function clampInt(v, min, max, fallback) {
    const n = parseInt(v, 10);
    if (Number.isNaN(n)) return fallback;
    return Math.max(min, Math.min(max, n));
  }

  function isLikelyCurl(text) {
    const t = text.trim();
    return /^curl(\s|$)/i.test(t);
  }

  function parseCurl(text) {
    // Note: not a full shell parser. Handles common patterns.
    // curl -X POST "https://x" -H "K: V" -H 'K2: V2' -d '{"a":1}' --cookie "a=b; c=d"
    let method = "GET";
    let url = "";
    let headers = {};
    let cookies = {};
    let body = null;

    // naive tokenization that respects simple quoted segments
    const tokens = [];
    const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let m;
    while ((m = re.exec(text)) !== null) tokens.push(m[1] ?? m[2] ?? m[3]);

    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];

      if (tok === "-X" || tok === "--request") {
        method = (tokens[++i] || method).toUpperCase();
        continue;
      }
      if (tok === "-H" || tok === "--header") {
        const hv = tokens[++i] || "";
        const mm = hv.match(/^([^:]+):\s*(.*)$/);
        if (mm) headers[mm[1].trim()] = mm[2].trim();
        continue;
      }
      if (tok === "-d" || tok === "--data" || tok === "--data-raw" || tok === "--data-binary") {
        body = tokens[++i] ?? "";
        if (method === "GET") method = "POST";
        continue;
      }
      if (tok === "-b" || tok === "--cookie") {
        const c = tokens[++i] || "";
        // "a=b; c=d"
        c.split(/;\s*/).forEach(pair => {
          const [k, ...rest] = pair.split("=");
          if (!k || rest.length === 0) return;
          cookies[k.trim()] = decodeURIComponent(rest.join("=").trim());
        });
        continue;
      }
      if (/^https?:\/\//i.test(tok)) {
        url = tok;
      }
    }

    return { method, url, headers, cookies, body };
  }

  function parseRawHttp(text) {
    // Raw HTTP request parsing approach matches the REQ2PY concept :contentReference[oaicite:4]{index=4}
    const lines = text.split("\n").map(l => l.replace(/\r$/, ""));
    const first = lines[0] || "";
    const m = first.match(/^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(.*?)\s+HTTP\/\d/i);
    if (!m) return null;

    let method = m[1].toUpperCase();
    let path = m[2];

    let headers = {};
    let cookies = {};
    let host = "";
    let inHeaders = true;
    let bodyLines = [];

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];

      if (inHeaders) {
        if (line.trim() === "") {
          inHeaders = false;
          continue;
        }
        const hm = line.match(/^([^:]+):\s*(.*)$/);
        if (!hm) continue;
        const k = hm[1].trim();
        const v = hm[2].trim();
        if (k.toLowerCase() === "host") host = v;
        else if (k.toLowerCase() === "cookie") {
          v.split(/;\s*/).forEach(pair => {
            const [ck, ...rest] = pair.split("=");
            if (!ck || rest.length === 0) return;
            cookies[ck.trim()] = decodeURIComponent(rest.join("=").trim());
          });
        } else {
          headers[k] = v;
        }
      } else {
        bodyLines.push(line);
      }
    }

    const body = bodyLines.length ? bodyLines.join("\n").trim() : null;

    // Build full URL if needed
    let url = path;
    if (!/^https?:\/\//i.test(url)) {
      if (!host) return { error: "Missing Host header (needed to build full URL)." };
      const scheme = "https"; // default
      url = `${scheme}://${host}${path.startsWith("/") ? "" : "/"}${path}`;
    }

    return { method, url, headers, cookies, body };
  }

  function pyDict(obj, indent = 4) {
    return JSON.stringify(obj, null, indent);
  }

  function pythonScriptTemplate({ method, url, headers, cookies, body, concurrency, rounds, timeout }) {
    const hasHeaders = headers && Object.keys(headers).length > 0;
    const hasCookies = cookies && Object.keys(cookies).length > 0;
    const hasBody = body !== null && body !== undefined && String(body).length > 0;

    // Try JSON body detection
    let bodyIsJson = false;
    let parsedJson = null;
    if (hasBody) {
      try {
        parsedJson = JSON.parse(body);
        bodyIsJson = true;
      } catch (_) {}
    }

    const headersBlock = hasHeaders
      ? `headers = ${pyDict(headers, 4)}\n\n`
      : `headers = {}\n\n`;

    const cookiesBlock = hasCookies
      ? `cookies = ${pyDict(cookies, 4)}\n\n`
      : `cookies = {}\n\n`;

    let bodyBlock = `payload = None\n\n`;
    if (hasBody && bodyIsJson) {
      bodyBlock = `payload = ${JSON.stringify(parsedJson, null, 4)}\n\n`;
    } else if (hasBody) {
      // raw body
      const safe = String(body).replace(/'''/g, "''\\''");
      bodyBlock = `payload_raw = r'''${safe}'''\npayload = payload_raw\n\n`;
    }

    return `#!/usr/bin/env python3
import time
import json
import hashlib
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests

# === CANNON: race-condition burst tester ===
# This script fires synchronized concurrent requests and compares responses for anomalies.
# Use only on systems you are authorized to test.

method = ${JSON.stringify(method)}
url = ${JSON.stringify(url)}

${headersBlock}${cookiesBlock}${bodyBlock}
CONCURRENCY = ${concurrency}  # max 10 recommended
ROUNDS = ${rounds}
TIMEOUT = ${timeout}

def _hash_body(body_bytes: bytes, limit=65536) -> str:
    if body_bytes is None:
        return "none"
    chunk = body_bytes[:limit]
    return hashlib.sha256(chunk).hexdigest()

def send_once(worker_id: int, barrier: threading.Barrier):
    # Each worker uses its own Session (requests.Session is not thread-safe when shared)
    s = requests.Session()
    kwargs = {
        "headers": headers,
        "cookies": cookies if cookies else None,
        "timeout": TIMEOUT,
        "allow_redirects": False,
    }

    # Prepare request body
    if payload is not None:
        if isinstance(payload, (dict, list)):
            kwargs["json"] = payload
        else:
            kwargs["data"] = payload

    # Synchronize start (key for race testing)
    barrier.wait()

    t0 = time.perf_counter()
    try:
        r = s.request(method, url, **kwargs)
        dt = (time.perf_counter() - t0) * 1000.0
        body_bytes = r.content
        return {
            "worker": worker_id,
            "ok": True,
            "status": r.status_code,
            "ms": dt,
            "len": len(body_bytes) if body_bytes is not None else 0,
            "hash": _hash_body(body_bytes),
            "headers": dict(r.headers),
            "text_snip": (r.text[:300] if r.text else ""),
        }
    except Exception as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return {
            "worker": worker_id,
            "ok": False,
            "status": None,
            "ms": dt,
            "len": 0,
            "hash": "error",
            "error": repr(e),
        }

def analyze_round(results):
    statuses = [x["status"] for x in results if x["ok"] and x["status"] is not None]
    hashes = [x["hash"] for x in results if x["ok"]]
    times = [x["ms"] for x in results]

    summary = {
        "count": len(results),
        "ok": sum(1 for x in results if x["ok"]),
        "errors": [x for x in results if not x["ok"]],
        "unique_statuses": sorted(set(statuses)),
        "unique_hashes": len(set(hashes)),
        "min_ms": min(times) if times else None,
        "max_ms": max(times) if times else None,
        "p50_ms": statistics.median(times) if times else None,
    }

    flags = []
    if len(summary["unique_statuses"]) > 1:
        flags.append("MULTIPLE_STATUS_CODES")
    if summary["unique_hashes"] > 1:
        flags.append("MULTIPLE_RESPONSE_BODIES")
    if summary["min_ms"] is not None and summary["max_ms"] is not None:
        if summary["max_ms"] - summary["min_ms"] > 500:
            flags.append("LARGE_TIMING_SKEW_GT_500MS")
    if summary["errors"]:
        flags.append("REQUEST_ERRORS_PRESENT")

    return summary, flags

def main():
    conc = int(CONCURRENCY)
    if conc < 1: conc = 1
    if conc > 10: conc = 10

    print(f"[+] Cannon firing: concurrency={conc}, rounds={ROUNDS}, timeout={TIMEOUT}s")
    print(f"[+] Target: {method} {url}")

    all_flags = []
    for rnd in range(1, ROUNDS + 1):
        barrier = threading.Barrier(conc)
        results = []
        with ThreadPoolExecutor(max_workers=conc) as ex:
            futs = [ex.submit(send_once, i, barrier) for i in range(conc)]
            for f in as_completed(futs):
                results.append(f.result())

        summary, flags = analyze_round(results)
        all_flags.extend(flags)

        print(f"\\n=== Round {rnd}/{ROUNDS} ===")
        print(f"OK: {summary['ok']}/{summary['count']}  Unique statuses: {summary['unique_statuses']}  Unique bodies: {summary['unique_hashes']}")
        print(f"Timing ms: min={summary['min_ms']:.2f}  p50={summary['p50_ms']:.2f}  max={summary['max_ms']:.2f}")
        if flags:
            print(f"[!] Flags: {', '.join(flags)}")

        # Show details when suspicious
        if "MULTIPLE_STATUS_CODES" in flags or "MULTIPLE_RESPONSE_BODIES" in flags:
            # group by status/hash
            print("[+] Sample results (worker/status/len/hash/ms):")
            for x in sorted(results, key=lambda z: (str(z["status"]), z["hash"], z["worker"]))[:min(10, len(results))]:
                print(f"  - w{x['worker']}  {x.get('status')}  len={x.get('len')}  hash={x.get('hash')[:12]}  ms={x.get('ms'):.2f}")

        if summary["errors"]:
            print("[!] Errors:")
            for e in summary["errors"]:
                print(f"  - w{e['worker']}: {e.get('error')}")

    print("\\n=== Overall ===")
    if all_flags:
        print("[!] Observed flags (across rounds):")
        for f in sorted(set(all_flags)):
            print(f"  - {f}")
    else:
        print("[+] No obvious anomalies observed. (Not proof of no race condition.)")

if __name__ == "__main__":
    main()
`;
  }

  function convert(text, concurrency, rounds, timeout) {
    const clean = sanitize(text);

    if (!clean.trim()) return "Paste a request first.";

    let parsed = null;
    if (isLikelyCurl(clean)) {
      parsed = parseCurl(clean);
      if (!parsed.url) return "Could not find a URL in the curl command.";
    } else {
      parsed = parseRawHttp(clean);
      if (!parsed) return "Could not parse raw HTTP request. (Expected: METHOD path HTTP/1.1 ...)";
      if (parsed.error) return parsed.error;
    }

    return pythonScriptTemplate({
      method: parsed.method,
      url: parsed.url,
      headers: parsed.headers || {},
      cookies: parsed.cookies || {},
      body: parsed.body,
      concurrency,
      rounds,
      timeout
    });
  }

  convertBtn.addEventListener("click", () => {
    const conc = clampInt(concurrencyEl.value, 1, 10, 5);
    const rounds = clampInt(roundsEl.value, 1, 50, 3);
    const timeout = clampInt(timeoutEl.value, 1, 120, 15);
    output.value = convert(input.value, conc, rounds, timeout);
  });

  copyBtn.addEventListener("click", () => {
    output.select();
    document.execCommand("copy");
    alert("Copied Cannon script to clipboard.");
  });
});
