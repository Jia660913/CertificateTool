const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 4177);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const JOBS_DIR = path.join(ROOT, ".jobs");
const CSI_BUNDLE_ROOT =
  process.env.CSI_BUNDLE_ROOT ||
  "C:\\Users\\z0242332\\OneDrive - ZF Friedrichshafen AG\\Desktop\\CSI_Bundle";
const CERTIFICATE_SAMPLE_DIR = path.join(CSI_BUNDLE_ROOT, "samples", "certificate-tool-cfg");
const EXE_PATH =
  process.env.CSI_CERT_TOOL_EXE ||
  "C:\\Users\\z0242332\\OneDrive - ZF Friedrichshafen AG\\Desktop\\CSI_Bundle\\bin\\windows\\x64\\CsiCertificateTool.exe";

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".cert": "application/octet-stream",
  ".txt": "text/plain; charset=utf-8"
};

fs.mkdirSync(JOBS_DIR, { recursive: true });

function send(res, status, body, contentType = "application/json; charset=utf-8") {
  const payload = typeof body === "string" ? body : JSON.stringify(body, null, 2);
  res.writeHead(status, { "Content-Type": contentType });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 25 * 1024 * 1024) {
        reject(new Error("Request body is too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(error);
      }
    });
  });
}

function sanitizeFileName(name, fallback) {
  const safe = String(name || fallback || "output.cert")
    .replace(/[<>:"/\\|?*\u0000-\u001F]/g, "-")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^\.+/, "")
    .slice(0, 120);
  return safe || fallback || "output.cert";
}

function writeUploadedFile(jobDir, file, fallbackName) {
  if (!file || !file.contentBase64) return null;
  const name = sanitizeFileName(file.name, fallbackName);
  const target = path.join(jobDir, name);
  fs.writeFileSync(target, Buffer.from(file.contentBase64, "base64"));
  return target;
}

function pickFilePath(jobDir, payload, field, fallbackName) {
  const uploaded = payload.uploadedFiles && payload.uploadedFiles[field];
  const saved = writeUploadedFile(jobDir, uploaded, fallbackName);
  if (saved) return saved;
  const fromPath = payload.paths && payload.paths[field];
  return fromPath ? String(fromPath) : "";
}

function addOptional(args, flag, value) {
  if (value !== undefined && value !== null && String(value).trim() !== "") {
    args.push(flag, String(value));
  }
}

function redactArgs(args) {
  const secretFlags = new Set(["--direct"]);
  const fileFlags = new Set(["--mtls", "--dda"]);
  const redacted = [];
  for (let i = 0; i < args.length; i += 1) {
    const current = args[i];
    redacted.push(current);
    if (secretFlags.has(current)) {
      redacted.push(args[++i] || "");
      redacted.push("***REDACTED***");
    } else if (fileFlags.has(current)) {
      redacted.push(args[++i] || "");
      redacted.push(args[++i] ? "***FILE***" : "");
      if (current === "--mtls") redacted.push(args[++i] ? "***FILE***" : "");
    }
  }
  return redacted.filter(Boolean);
}

function buildArgs(payload, configPath, outputPath, jobDir) {
  const form = payload.form || {};
  const run = form.run || {};
  const signature = form.signature || {};
  const dlm = form.dlmConnection || {};
  const args = [];

  if (run.noColors !== false) args.push("--no_colors");
  if (run.verbose) args.push("--verbose");
  if (run.disableZf1 && run.runMode === "offline") args.push("--no_zf1");
  addOptional(args, "--hash", run.hashAlgorithm || "SHA256");

  if (run.runMode === "dlm") {
    args.push("--dlm");
    const type = dlm.type;
    if (type === "direct") {
      args.push("--direct", dlm.directUri || "default", dlm.jwt || "");
    } else if (type === "mtls") {
      const pem = pickFilePath(jobDir, payload, "mtlsPemFile", "client.pem");
      const key = pickFilePath(jobDir, payload, "mtlsKeyFile", "client.key");
      args.push("--mtls", dlm.mtlsUri || "default", pem, key);
      const chain = pickFilePath(jobDir, payload, "mtlsChainFile", "chain.pem");
      if (chain) args.push("--mtls_chain", chain);
    } else if (type === "dsa") {
      args.push("--dsa");
    } else if (type === "dda") {
      const token = pickFilePath(jobDir, payload, "proximaTokenFile", "proxima-token.txt");
      args.push("--dda", dlm.ddaUri || "default", token);
    } else if (type === "aa") {
      const enrollment = pickFilePath(jobDir, payload, "enrollmentFile", "enrollment.json");
      const metadata = pickFilePath(jobDir, payload, "metadataFile", "metadata.json");
      args.push("--aa", dlm.autoAuthUri || "default", "-e", enrollment, "-m", metadata);
    }

    if ((type === "dsa" || type === "dda") && dlm.proximaUri) {
      args.push("--proxima", dlm.proximaUri);
    }
    if ((type === "direct" || type === "dsa") && dlm.async) {
      args.push("--async");
    }
    const bpParamsFile = pickFilePath(jobDir, payload, "bpParamsFile", "bp-params.json");
    if (bpParamsFile) args.push("--params", bpParamsFile);
    addOptional(args, "--httpproxy", dlm.httpProxy);
  } else {
    args.push("--offline");
  }

  args.push("-c", configPath, "-o", outputPath);
  return args;
}

function serveStatic(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const requested = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const target = path.normalize(path.join(PUBLIC_DIR, requested));
  if (!target.startsWith(PUBLIC_DIR)) return send(res, 403, "Forbidden", "text/plain");
  fs.readFile(target, (error, data) => {
    if (error) return send(res, 404, "Not found", "text/plain");
    res.writeHead(200, { "Content-Type": MIME_TYPES[path.extname(target)] || "application/octet-stream" });
    res.end(data);
  });
}

function serveSamples(req, res) {
  if (req.method !== "GET") return false;
  if (req.url === "/api/samples") {
    if (!fs.existsSync(CERTIFICATE_SAMPLE_DIR)) {
      send(res, 404, { error: "Certificate sample directory was not found.", path: CERTIFICATE_SAMPLE_DIR });
      return true;
    }
    const files = fs
      .readdirSync(CERTIFICATE_SAMPLE_DIR)
      .filter((file) => file.toLowerCase().endsWith(".json"))
      .sort()
      .map((file) => ({
        name: file,
        mode: file.toLowerCase().includes("offline") ? "offline" : "dlm",
        path: path.join(CERTIFICATE_SAMPLE_DIR, file)
      }));
    send(res, 200, { sampleDir: CERTIFICATE_SAMPLE_DIR, files });
    return true;
  }

  const match = req.url.match(/^\/api\/samples\/([^/]+)$/);
  if (!match) return false;
  const fileName = sanitizeFileName(decodeURIComponent(match[1]), "sample.json");
  if (!fileName.toLowerCase().endsWith(".json")) {
    send(res, 400, { error: "Only JSON samples can be loaded." });
    return true;
  }
  const target = path.join(CERTIFICATE_SAMPLE_DIR, fileName);
  if (!target.startsWith(CERTIFICATE_SAMPLE_DIR) || !fs.existsSync(target)) {
    send(res, 404, { error: "Sample was not found.", fileName });
    return true;
  }
  try {
    const config = JSON.parse(fs.readFileSync(target, "utf8"));
    send(res, 200, { name: fileName, path: target, config });
  } catch (error) {
    send(res, 500, { error: error.message, fileName });
  }
  return true;
}

function serveJobFile(req, res) {
  const match = req.url.match(/^\/api\/jobs\/([^/]+)\/(output|config)$/);
  if (!match) return false;
  const jobId = match[1];
  const kind = match[2];
  const fileName = kind === "config" ? "generated-config.json" : "output.cert";
  const target = path.join(JOBS_DIR, jobId, fileName);
  if (!target.startsWith(JOBS_DIR) || !fs.existsSync(target)) {
    send(res, 404, { error: "File not found." });
    return true;
  }
  const contentType = kind === "config" ? MIME_TYPES[".json"] : MIME_TYPES[".cert"];
  let downloadName = fileName;
  const metaPath = path.join(JOBS_DIR, jobId, "meta.json");
  if (kind === "output" && fs.existsSync(metaPath)) {
    try {
      const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
      downloadName = sanitizeFileName(meta.outputFileName, fileName);
    } catch {
      downloadName = fileName;
    }
  }
  res.writeHead(200, {
    "Content-Type": contentType,
    "Content-Disposition": `attachment; filename="${downloadName}"`
  });
  fs.createReadStream(target).pipe(res);
  return true;
}

async function handleRun(req, res) {
  try {
    const payload = await readJson(req);
    const jobId = crypto.randomUUID();
    const jobDir = path.join(JOBS_DIR, jobId);
    fs.mkdirSync(jobDir, { recursive: true });

    const configPath = path.join(jobDir, "generated-config.json");
    const outputName = sanitizeFileName(payload.outputFileName || "output.cert", "output.cert");
    const outputPath = path.join(jobDir, outputName.endsWith(".cert") ? outputName : `${outputName}.cert`);
    const canonicalOutput = path.join(jobDir, "output.cert");

    fs.writeFileSync(path.join(jobDir, "meta.json"), JSON.stringify({ outputFileName: path.basename(outputPath) }, null, 2), "utf8");
    fs.writeFileSync(configPath, JSON.stringify(payload.config, null, 2), "utf8");
    const args = buildArgs(payload, configPath, outputPath, jobDir);
    const redactedCommand = `"${EXE_PATH}" ${redactArgs(args).map((arg) => `"${arg}"`).join(" ")}`;

    if (!fs.existsSync(EXE_PATH)) {
      return send(res, 500, {
        jobId,
        exitCode: null,
        command: redactedCommand,
        error: "CsiCertificateTool.exe was not found.",
        exePath: EXE_PATH,
        configUrl: `/api/jobs/${jobId}/config`
      });
    }

    const child = spawn(EXE_PATH, args, { windowsHide: true });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), 5 * 60 * 1000);
    child.stdout.on("data", (data) => (stdout += data.toString()));
    child.stderr.on("data", (data) => (stderr += data.toString()));
    child.on("close", (code) => {
      clearTimeout(timer);
      if (fs.existsSync(outputPath) && outputPath !== canonicalOutput) {
        fs.copyFileSync(outputPath, canonicalOutput);
      }
      send(res, 200, {
        jobId,
        exitCode: code,
        command: redactedCommand,
        stdout,
        stderr,
        outputUrl: fs.existsSync(canonicalOutput) ? `/api/jobs/${jobId}/output` : null,
        configUrl: `/api/jobs/${jobId}/config`
      });
    });
  } catch (error) {
    send(res, 500, { error: error.message });
  }
}

const server = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/api/run") return handleRun(req, res);
  if (serveSamples(req, res)) return;
  if (req.method === "GET" && serveJobFile(req, res)) return;
  if (req.method === "GET") return serveStatic(req, res);
  send(res, 405, { error: "Method not allowed." });
});

server.listen(PORT, () => {
  console.log(`CSI Certificate Wizard: http://localhost:${PORT}`);
  console.log(`Using CsiCertificateTool: ${EXE_PATH}`);
});
