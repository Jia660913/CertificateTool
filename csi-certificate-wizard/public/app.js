const app = document.getElementById("app");

const SCHEMES = [
  "RSASSA-PSS-ZF1-2048",
  "RSASSA-PSS-ZF1-3072",
  "RSASSA-PSS-ZF1-4096",
  "RSASSA-PSS-ZF1-4096-SHA512",
  "RSASSA-PSS-2048",
  "RSASSA-PSS-3072",
  "RSASSA-PSS-4096",
  "RSASSA-PSS-4096-SHA512",
  "ED25519-ZF1-SHA512",
  "ECDSA-ZF1-SECP256R1",
  "ECDSA-ZF1-SECP384R1",
  "ECDSA-ZF1-SECP521R1",
  "ECDSA-SECP384R1",
  "ECDSA-ZF-SECP256R1",
  "ECDSA-ZF-SECP521R1",
  "ED25519-ZF-SHA512"
];

const URI_OPTIONS = {
  direct: ["default", "productive1", "productive2", "qa", "hosted", "custom"],
  mtls: ["default", "qa", "shanghai", "shenyang", "custom"],
  dda: ["default", "qa", "shanghai", "shenyang", "custom"],
  aa: ["default", "productive", "staging", "custom"],
  proxima: ["default", "europe", "china", "custom"]
};

const STEPS = [
  { id: "start", name: "开始", desc: "选择模板或导入 JSON" },
  { id: "data", name: "证书信息", desc: "填写证书主体数据" },
  { id: "signature", name: "签名设置", desc: "选择签名字段和区域" },
  { id: "method", name: "签名来源", desc: "Offline 或 DLM" },
  { id: "details", name: "签名参数", desc: "填写 key 或 DLM 凭证" },
  { id: "output", name: "输出设置", desc: "文件名和运行选项" },
  { id: "review", name: "确认", desc: "检查 JSON 和命令" },
  { id: "result", name: "结果", desc: "日志和下载" }
];

function sampleNodes() {
  return [
    { id: "n1", parentId: null, order: 1, asn1Type: "Sequence", asn1Class: "Application", tag: 16, variableName: "" },
    { id: "n2", parentId: "n1", order: 1, asn1Type: "OctetString", asn1Class: "Application", tag: 1, variableName: "version" },
    { id: "n3", parentId: "n1", order: 2, asn1Type: "UTF8String", asn1Class: "Application", tag: 3, variableName: "certificateSerialNumber" },
    { id: "n4", parentId: "n1", order: 3, asn1Type: "UTF8String", asn1Class: "Application", tag: 5, variableName: "subjectId" },
    { id: "n5", parentId: "n1", order: 4, asn1Type: "OctetString", asn1Class: "Application", tag: 9, variableName: "publicKeyModulo" },
    { id: "n6", parentId: "n1", order: 5, asn1Type: "OctetString", asn1Class: "Application", tag: 11, variableName: "publicKeyExponent" },
    { id: "n7", parentId: "n1", order: 6, asn1Type: "OctetString", asn1Class: "Application", tag: 30, variableName: "signature" }
  ];
}

const state = {
  step: 0,
  templateMode: "basic",
  nodes: sampleNodes(),
  data: {
    version: "0x020000",
    certificateSerialNumber: "00000007",
    subjectId: "0z600851",
    publicKeyModulo: "",
    publicKeyExponent: "0x00010001"
  },
  signature: {
    enabled: true,
    field: "signature",
    regions: [{ startIndex: 4, length: 291 }]
  },
  run: {
    runMode: "offline",
    outputFileName: "output.cert",
    verbose: false,
    noColors: true,
    hashAlgorithm: "SHA256",
    disableZf1: false
  },
  offline: {
    schemeName: "ECDSA-ZF-SECP256R1",
    keyDataPrivate: "",
    publicKeyType: "hex",
    keyDataPublicHex: "",
    keyDataPublicExponent: "65537",
    keyDataPublicModulus: "",
    rawAdditionalDataHex: "0x50FA444400000000",
    sha512: false
  },
  dlm: {
    type: "dsa",
    credentialType: "dsa",
    productId: "",
    buildId: "",
    groupId: "",
    ecuId: "",
    projectId: "",
    componentId: "",
    bpParams: "",
    directUri: "default",
    directCustomUri: "",
    jwt: "",
    mtlsUri: "default",
    mtlsCustomUri: "",
    ddaUri: "default",
    ddaCustomUri: "",
    autoAuthUri: "default",
    autoAuthCustomUri: "",
    proximaUri: "default",
    proximaCustomUri: "",
    httpProxy: "",
    async: false
  },
  paths: {},
  uploadedFiles: {},
  samples: [],
  selectedSample: "",
  sampleDir: "",
  errors: {},
  result: null,
  busy: false
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getAt(path) {
  return path.split(".").reduce((target, key) => (target ? target[key] : undefined), state);
}

function setAt(path, value) {
  const keys = path.split(".");
  let target = state;
  while (keys.length > 1) {
    const key = keys.shift();
    target = target[key];
  }
  target[keys[0]] = value;
}

function asBool(value) {
  return value === true || value === "true" || value === "on";
}

function optionList(options, selected) {
  return options
    .map((item) => {
      const value = typeof item === "string" ? item : item.value;
      const label = typeof item === "string" ? item : item.label;
      return `<option value="${escapeHtml(value)}" ${String(selected) === String(value) ? "selected" : ""}>${escapeHtml(label)}</option>`;
    })
    .join("");
}

function fieldCard({ path, label, badge = "必填", badgeType = "required", help, format, example, control, error, wide = false }) {
  return `
    <div class="field-card ${error ? "error" : ""} ${wide ? "wide" : ""}">
      <div class="field-top">
        <div class="field-label">${escapeHtml(label)}</div>
        <span class="badge ${badgeType}">${escapeHtml(badge)}</span>
      </div>
      <div class="field-help">${help}</div>
      ${(format || example) ? `
        <div class="field-meta">
          ${format ? `<div>格式：${format}</div>` : ""}
          ${example ? `<div>示例：${example}</div>` : ""}
        </div>
      ` : ""}
      ${control}
      ${error ? `<div class="error-text">${escapeHtml(error)}</div>` : ""}
    </div>
  `;
}

function textInput(path, placeholder = "", type = "text") {
  const value = getAt(path) ?? "";
  return `<input class="input" type="${type}" data-bind="${path}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" />`;
}

function textArea(path, placeholder = "", short = false, secret = false) {
  const value = getAt(path) ?? "";
  return `<textarea class="textarea ${short ? "short" : ""}" data-bind="${path}" ${secret ? "data-secret=\"true\"" : ""} placeholder="${escapeHtml(placeholder)}">${escapeHtml(value)}</textarea>`;
}

function selectInput(path, options) {
  const selected = getAt(path);
  return `<select class="select" data-bind="${path}">${optionList(options, selected)}</select>`;
}

function checkInput(path, label) {
  const checked = asBool(getAt(path));
  return `
    <label class="inline-check">
      <input type="checkbox" data-bind="${path}" ${checked ? "checked" : ""} />
      ${escapeHtml(label)}
    </label>
  `;
}

function fileInput(field, label) {
  const uploaded = state.uploadedFiles[field];
  const pathValue = state.paths[field] || "";
  return `
    <div class="control-row">
      <input class="input" type="file" data-file="${field}" aria-label="${escapeHtml(label)}" />
      <input class="input" data-path-field="${field}" value="${escapeHtml(pathValue)}" placeholder="或填写后端可访问的本地文件路径" />
    </div>
    <div class="field-meta" style="margin-top:8px">
      <div>当前文件：${uploaded ? escapeHtml(uploaded.name) : "未上传"}</div>
    </div>
  `;
}

function uriSelector(path, customPath, options) {
  const current = getAt(path);
  const showCustom = current === "custom";
  return `
    ${selectInput(path, options)}
    ${showCustom ? `<div style="margin-top:8px">${textInput(customPath, "https://...")}</div>` : ""}
  `;
}

function classToken(value) {
  return {
    Universal: "UNIVERSAL",
    Application: "APPLICATION",
    ContextSpecific: "CONTEXTSPECIFIC",
    Private: "PRIVATE"
  }[value] || value;
}

function typeToken(value) {
  return value || "OctetString";
}

function nodeKey(node) {
  return `${typeToken(node.asn1Type)}:${classToken(node.asn1Class)}:${Number(node.tag) || 0}`;
}

function sequenceNodes() {
  return state.nodes.filter((node) => node.asn1Type === "Sequence");
}

function variableNodes() {
  return state.nodes.filter((node) => node.asn1Type !== "Sequence" && node.variableName);
}

function buildChildren(parentId) {
  const children = state.nodes
    .filter((node) => node.parentId === parentId)
    .sort((a, b) => Number(a.order) - Number(b.order));
  const obj = {};
  for (const child of children) {
    if (child.asn1Type === "Sequence") {
      obj[nodeKey(child)] = buildChildren(child.id);
    } else {
      obj[nodeKey(child)] = child.variableName;
    }
  }
  return obj;
}

function buildStructure() {
  return buildChildren(null);
}

function buildData() {
  const data = {};
  const signatureField = state.signature.enabled ? state.signature.field : "";
  for (const node of variableNodes()) {
    if (signatureField && node.variableName === signatureField) continue;
    const value = state.data[node.variableName];
    if (value !== undefined && value !== "") data[node.variableName] = value;
  }
  return data;
}

function currentUri(valuePath, customPath) {
  const value = getAt(valuePath);
  return value === "custom" ? getAt(customPath) : value;
}

function buildConfig() {
  const config = {
    Structure: buildStructure(),
    Data: buildData()
  };

  if (state.signature.enabled) {
    const signature = {
      Field: state.signature.field,
      Regions: state.signature.regions.map((region) => [Number(region.startIndex), Number(region.length)])
    };

    if (state.run.runMode === "offline") {
      signature.SchemeName = state.offline.schemeName;
      signature.KeyDataPrivate = state.offline.keyDataPrivate;
      signature.KeyDataPublic =
        state.offline.publicKeyType === "rsaObject"
          ? {
              Exponent: state.offline.keyDataPublicExponent,
              Modulus: state.offline.keyDataPublicModulus
            }
          : state.offline.keyDataPublicHex;
      if (state.offline.rawAdditionalDataHex) signature.RawAdditionalDataHex = state.offline.rawAdditionalDataHex;
      if (state.offline.sha512) signature.Sha512 = true;
    } else {
      signature.ProductId = state.dlm.productId;
      signature.BuildId = state.dlm.buildId;
      signature.GroupId = state.dlm.groupId;
      if (state.dlm.ecuId) signature.EcuId = state.dlm.ecuId;
      if (state.dlm.projectId) signature.ProjectId = state.dlm.projectId;
      if (state.dlm.componentId) signature.ComponentId = state.dlm.componentId;
      if (state.dlm.bpParams) {
        try {
          signature.BpParams = JSON.parse(state.dlm.bpParams);
        } catch {
          signature.BpParams = state.dlm.bpParams;
        }
      }
    }

    config.Signature = signature;
  }

  return config;
}

function buildCommandPreview() {
  const args = [];
  if (state.run.noColors !== false) args.push("--no_colors");
  if (state.run.verbose) args.push("--verbose");
  if (state.run.disableZf1 && state.run.runMode === "offline") args.push("--no_zf1");
  args.push("--hash", state.run.hashAlgorithm || "SHA256");

  if (state.run.runMode === "offline") {
    args.push("--offline");
  } else {
    args.push("--dlm");
    if (state.dlm.type === "direct") args.push("--direct", currentUri("dlm.directUri", "dlm.directCustomUri"), "***JWT_REDACTED***");
    if (state.dlm.type === "mtls") args.push("--mtls", currentUri("dlm.mtlsUri", "dlm.mtlsCustomUri"), "***PEM***", "***KEY***");
    if (state.dlm.type === "dsa") args.push("--dsa");
    if (state.dlm.type === "dda") args.push("--dda", currentUri("dlm.ddaUri", "dlm.ddaCustomUri"), "***TOKEN_FILE***");
    if (state.dlm.type === "aa") args.push("--aa", currentUri("dlm.autoAuthUri", "dlm.autoAuthCustomUri"), "-e", "***ENROLLMENT***", "-m", "***METADATA***");
    if ((state.dlm.type === "dsa" || state.dlm.type === "dda") && state.dlm.proximaUri) {
      args.push("--proxima", currentUri("dlm.proximaUri", "dlm.proximaCustomUri"));
    }
    if (state.dlm.httpProxy) args.push("--httpproxy", state.dlm.httpProxy);
    if ((state.dlm.type === "direct" || state.dlm.type === "dsa") && state.dlm.async) args.push("--async");
  }

  args.push("-c", "generated-config.json", "-o", state.run.outputFileName || "output.cert");
  return `CsiCertificateTool.exe ${args.map((item) => `"${item}"`).join(" ")}`;
}

function isHex(value, allowEmpty = false) {
  if (allowEmpty && !value) return true;
  return /^0x[0-9a-fA-F]*$/.test(String(value || "")) && String(value).length % 2 === 0;
}

function setError(errors, path, message) {
  errors[path] = message;
}

function validateStep(step = state.step) {
  const errors = {};
  if (step === 0 && !state.templateMode) {
    setError(errors, "templateMode", "请选择一种证书配置方式。");
  }

  if (step === 1) {
    if (state.templateMode === "advanced") {
      for (const node of state.nodes) {
        if (node.asn1Type !== "Sequence" && !node.variableName) {
          setError(errors, `node.${node.id}.variableName`, "非 Sequence 节点必须填写变量名。");
        }
      }
    }
    for (const node of variableNodes()) {
      if (state.signature.enabled && node.variableName === state.signature.field) continue;
      const value = state.data[node.variableName];
      if (value === undefined || value === "") setError(errors, `data.${node.variableName}`, "此字段必填。");
      if (node.asn1Type === "OctetString" && value && !isHex(value) && !/^\d+$/.test(String(value))) {
        setError(errors, `data.${node.variableName}`, "OctetString 建议填写 0x 开头的十六进制字符串，或整数。");
      }
    }
  }

  if (step === 2 && state.signature.enabled) {
    if (!state.signature.field) setError(errors, "signature.field", "请选择签名写入字段。");
    if (!state.signature.regions.length) setError(errors, "signature.regions", "至少需要一个签名区域。");
    state.signature.regions.forEach((region, index) => {
      if (region.startIndex === "" || Number(region.startIndex) < 0) setError(errors, `signature.regions.${index}.startIndex`, "起始位置必须是非负整数。");
      if (region.length === "" || Number(region.length) <= 0) setError(errors, `signature.regions.${index}.length`, "长度必须大于 0。");
    });
  }

  if (step === 3 && !state.run.runMode) {
    setError(errors, "run.runMode", "请选择 Offline 或 DLM。");
  }

  if (step === 4 && state.signature.enabled) {
    if (state.run.runMode === "offline") {
      if (!state.offline.schemeName) setError(errors, "offline.schemeName", "请选择离线签名算法。");
      if (!state.offline.keyDataPrivate) setError(errors, "offline.keyDataPrivate", "请填写私钥。");
      if (state.offline.publicKeyType === "hex" && !state.offline.keyDataPublicHex) setError(errors, "offline.keyDataPublicHex", "请填写公钥。");
      if (state.offline.publicKeyType === "rsaObject") {
        if (!state.offline.keyDataPublicExponent) setError(errors, "offline.keyDataPublicExponent", "请填写 RSA exponent。");
        if (!state.offline.keyDataPublicModulus) setError(errors, "offline.keyDataPublicModulus", "请填写 RSA modulus。");
      }
      if (state.offline.rawAdditionalDataHex && !isHex(state.offline.rawAdditionalDataHex)) {
        setError(errors, "offline.rawAdditionalDataHex", "Additional data 必须是 0x 开头的十六进制字符串。");
      }
    } else {
      if (!state.dlm.productId) setError(errors, "dlm.productId", "请填写 Product ID。");
      if (!state.dlm.buildId) setError(errors, "dlm.buildId", "请填写 Build ID。");
      if (!state.dlm.groupId) setError(errors, "dlm.groupId", "请填写 Group ID。");
      if (state.dlm.type === "direct") {
        if (!currentUri("dlm.directUri", "dlm.directCustomUri")) setError(errors, "dlm.directUri", "请填写 Direct URI。");
        if (!state.dlm.jwt) setError(errors, "dlm.jwt", "请填写 JWT token。");
      }
      if (state.dlm.type === "mtls") {
        if (!currentUri("dlm.mtlsUri", "dlm.mtlsCustomUri")) setError(errors, "dlm.mtlsUri", "请填写 mTLS URI。");
        if (!state.uploadedFiles.mtlsPemFile && !state.paths.mtlsPemFile) setError(errors, "file.mtlsPemFile", "请上传 PEM 或填写路径。");
        if (!state.uploadedFiles.mtlsKeyFile && !state.paths.mtlsKeyFile) setError(errors, "file.mtlsKeyFile", "请上传 KEY 或填写路径。");
      }
      if (state.dlm.type === "dda") {
        if (!currentUri("dlm.ddaUri", "dlm.ddaCustomUri")) setError(errors, "dlm.ddaUri", "请填写 DDA URI。");
        if (!state.uploadedFiles.proximaTokenFile && !state.paths.proximaTokenFile) setError(errors, "file.proximaTokenFile", "请上传 Proxima Token 或填写路径。");
      }
      if (state.dlm.type === "aa") {
        if (!currentUri("dlm.autoAuthUri", "dlm.autoAuthCustomUri")) setError(errors, "dlm.autoAuthUri", "请填写 AutoAuth URI。");
        if (!state.uploadedFiles.enrollmentFile && !state.paths.enrollmentFile) setError(errors, "file.enrollmentFile", "请上传 Enrollment 文件或填写路径。");
        if (!state.uploadedFiles.metadataFile && !state.paths.metadataFile) setError(errors, "file.metadataFile", "请上传 Metadata 文件或填写路径。");
      }
    }
  }

  if (step === 5 && !state.run.outputFileName) {
    setError(errors, "run.outputFileName", "请填写输出文件名。");
  }

  state.errors = errors;
  return Object.keys(errors).length === 0;
}

function stepHtml() {
  return STEPS.map((step, index) => `
    <div class="step-item ${index === state.step ? "active" : ""} ${index < state.step ? "done" : ""}">
      <div class="step-number">${index + 1}</div>
      <div>
        <div class="step-name">${escapeHtml(step.name)}</div>
        <div class="step-desc">${escapeHtml(step.desc)}</div>
      </div>
    </div>
  `).join("");
}

function pageHead(title, copy, badge = "") {
  return `
    <div class="page-head">
      <div>
        <h1 class="page-title">${escapeHtml(title)}</h1>
        <p class="page-copy">${copy}</p>
      </div>
      ${badge ? `<span class="status-pill">${escapeHtml(badge)}</span>` : ""}
    </div>
  `;
}

function renderStart() {
  return `
    ${pageHead("选择证书生成方式", "普通用户使用内置证书模板即可。系统会根据表单生成 JSON，再调用 CsiCertificateTool.exe。", "推荐：模板生成")}
    <div class="section">
      <div class="section-title"><h2>桌面 CSI_Bundle 样例演示</h2><span class="badge ok">推荐先试</span></div>
      <p class="section-note">这里直接读取桌面 <code>CSI_Bundle\\samples\\certificate-tool-cfg</code> 里的真实样例。选择一个样例后，系统会自动反填表单，你可以逐页查看逻辑是否正确。</p>
      <div class="grid">
        ${fieldCard({
          label: "选择桌面样例",
          badge: "演示",
          badgeType: "ok",
          help: "选择真实 certificate-tool 配置样例。offline 样例可以直接运行；DLM 样例会反填 Product/Build/Group，但实际运行还需要你的 DLM 凭证和网络条件。",
          format: "来自本地 CSI_Bundle",
          example: "offline-ecdsa-zf1-secp256r1.json",
          control: `
            <div class="control-row">
              <select class="select" data-bind="selectedSample">
                <option value="">请选择样例</option>
                ${optionList(state.samples.map((item) => ({ value: item.name, label: `${item.mode.toUpperCase()} - ${item.name}` })), state.selectedSample)}
              </select>
              <button class="btn primary" data-action="load-sample" ${state.selectedSample ? "" : "disabled"}>加载样例</button>
            </div>
          `,
          error: state.errors.sample
        })}
        ${fieldCard({
          label: "样例目录",
          badge: "只读",
          badgeType: "optional",
          help: "后端只读取这个目录中的 certificate-tool JSON 样例，不会修改 CSI_Bundle。",
          format: "本地路径",
          example: "samples\\certificate-tool-cfg",
          control: `<input class="input" disabled value="${escapeHtml(state.sampleDir || "正在读取样例目录...")}" />`
        })}
      </div>
    </div>
    <div class="section">
      <div class="section-title"><h2>手动开始</h2><span class="badge optional">可选</span></div>
    </div>
    <div class="choice-grid">
      ${choiceCard("basic", "内置证书模板", "按样例证书结构生成证书。用户只填写业务字段和签名参数，最适合第一版上线。")}
      ${choiceCard("import", "导入已有 JSON", "上传已有配置并反填到表单。适合支持人员或已经有配置文件的用户。")}
      ${choiceCard("advanced", "高级自定义结构", "构造 ASN.1 Structure，适合需要自定义证书结构的高级用户。")}
    </div>
    <div class="section ${state.templateMode === "import" ? "" : "hidden"}">
      <div class="notice">上传 JSON 后，系统会尝试解析 Structure、Data、Signature，并填回后续表单。导入后仍然可以逐项修改。</div>
      ${fieldCard({
        label: "导入 config.json",
        badge: "可选",
        badgeType: "optional",
        help: "选择已有 Certificate Tool 配置文件。文件只在浏览器中读取，用于反填表单。",
        format: "JSON",
        example: "offline-ecdsa-zf1-secp256r1.json",
        control: `<input class="input" type="file" accept=".json,application/json" data-import-json />`,
        error: state.errors.importJson
      })}
    </div>
  `;
}

function choiceCard(value, title, copy) {
  return `
    <button class="choice-card ${state.templateMode === value ? "selected" : ""}" data-action="set-template" data-value="${value}">
      <div class="choice-title">${escapeHtml(title)}</div>
      <div class="choice-copy">${escapeHtml(copy)}</div>
    </button>
  `;
}

function dataFieldForNode(node) {
  const path = `data.${node.variableName}`;
  const typeHelp = {
    version: "定义证书版本。普通用户通常保持默认值即可。",
    certificateSerialNumber: "证书序列号，用于区分不同证书。",
    subjectId: "证书主体 ID，表示该证书对应的对象或设备身份。",
    publicKeyModulo: "写入证书主体公钥的 modulus。通常是一段很长的十六进制数据。",
    publicKeyExponent: "写入证书主体公钥的 exponent。RSA 常见值是 0x00010001。",
    signature: "签名输出字段。启用签名时由工具自动写入，用户不需要填写。"
  };
  const isSignature = state.signature.enabled && node.variableName === state.signature.field;
  if (isSignature) {
    return fieldCard({
      label: node.variableName,
      badge: "自动生成",
      badgeType: "ok",
      help: typeHelp[node.variableName] || "该变量由签名计算结果自动填充。",
      format: `${node.asn1Type}:${node.asn1Class}:${node.tag}`,
      example: "由工具写入",
      control: `<input class="input" disabled value="签名启用时由 CsiCertificateTool 自动写入" />`
    });
  }
  const control = node.asn1Type === "Boolean"
    ? selectInput(path, [{ value: "true", label: "true" }, { value: "false", label: "false" }])
    : node.variableName.toLowerCase().includes("modulo")
      ? textArea(path, "0x...", false)
      : textInput(path, node.asn1Type === "OctetString" ? "0x..." : "");
  return fieldCard({
    label: node.variableName,
    badge: "必填",
    badgeType: "required",
    help: typeHelp[node.variableName] || "该值会写入证书 Data 区域，变量名来自 Structure。",
    format: `${node.asn1Type}:${node.asn1Class}:${node.tag}`,
    example: node.asn1Type === "OctetString" ? "0xABCD" : "文本或整数",
    control,
    error: state.errors[path]
  });
}

function renderData() {
  const isAdvanced = state.templateMode === "advanced";
  return `
    ${pageHead(isAdvanced ? "构造证书结构并填写数据" : "填写证书基础信息", isAdvanced ? "高级模式允许修改 ASN.1 Structure。每个非 Sequence 节点都会自动生成一个 Data 输入项。" : "当前使用内置证书模板。你只需要填写证书业务字段，系统会自动生成 Structure 和 Data。", isAdvanced ? "高级模式" : "模板模式")}
    ${isAdvanced ? renderStructureBuilder() : ""}
    <div class="section">
      <div class="section-title"><h2>证书 Data 字段</h2><span class="badge required">逐项填写</span></div>
      <p class="section-note">这些输入会写入生成的 <code>config.json</code> 的 <code>Data</code> 区域。</p>
      <div class="grid">
        ${variableNodes().map(dataFieldForNode).join("")}
      </div>
    </div>
  `;
}

function renderStructureBuilder() {
  const parentOptions = [{ value: "", label: "Root" }].concat(sequenceNodes().map((node) => ({
    value: node.id,
    label: `${node.id} - ${node.asn1Type}:${node.asn1Class}:${node.tag}`
  })));
  return `
    <div class="section">
      <div class="section-title">
        <h2>ASN.1 Structure Builder</h2>
        <div class="button-group">
          <button class="btn" data-action="add-node" data-kind="value">新增字段</button>
          <button class="btn" data-action="add-node" data-kind="sequence">新增 Sequence</button>
        </div>
      </div>
      <p class="section-note">每一行会生成一个 Structure 节点。字段顺序会影响证书字节布局，也会影响签名区域。</p>
      ${state.nodes.map((node) => renderNodeRow(node, parentOptions)).join("")}
    </div>
  `;
}

function renderNodeRow(node, parentOptions) {
  return `
    <div class="node-row">
      <div>
        <label class="small-label">Type</label>
        <select class="select" data-node="${node.id}" data-node-field="asn1Type">
          ${optionList(["Sequence", "OctetString", "UTF8String", "Integer", "Boolean"], node.asn1Type)}
        </select>
      </div>
      <div>
        <label class="small-label">Class</label>
        <select class="select" data-node="${node.id}" data-node-field="asn1Class">
          ${optionList(["Universal", "Application", "ContextSpecific", "Private"], node.asn1Class)}
        </select>
      </div>
      <div>
        <label class="small-label">Tag</label>
        <input class="input" type="number" min="0" max="31" data-node="${node.id}" data-node-field="tag" value="${escapeHtml(node.tag)}" />
      </div>
      <div>
        <label class="small-label">Parent</label>
        <select class="select" data-node="${node.id}" data-node-field="parentId">
          ${optionList(parentOptions.filter((item) => item.value !== node.id), node.parentId || "")}
        </select>
      </div>
      <div>
        <label class="small-label">Variable</label>
        <input class="input" data-node="${node.id}" data-node-field="variableName" value="${escapeHtml(node.variableName || "")}" ${node.asn1Type === "Sequence" ? "disabled" : ""} />
      </div>
      <div>
        <label class="small-label">Order</label>
        <input class="input" type="number" data-node="${node.id}" data-node-field="order" value="${escapeHtml(node.order)}" />
      </div>
      <button class="btn danger" data-action="delete-node" data-id="${node.id}" ${state.nodes.length <= 1 ? "disabled" : ""}>删除</button>
    </div>
    ${state.errors[`node.${node.id}.variableName`] ? `<div class="error-text">${escapeHtml(state.errors[`node.${node.id}.variableName`])}</div>` : ""}
  `;
}

function renderSignature() {
  const variables = variableNodes().map((node) => node.variableName);
  return `
    ${pageHead("配置签名", "普通用户建议保持默认签名字段和模板签名区域。高级用户可以手动编辑 Regions。", state.signature.enabled ? "签名开启" : "跳过签名")}
    <div class="grid">
      ${fieldCard({
        label: "是否生成签名",
        badge: "必选",
        badgeType: "required",
        help: "开启后系统会生成 Signature 配置，工具会计算签名并写入证书。",
        format: "开关",
        example: "默认开启",
        control: checkInput("signature.enabled", "生成带签名证书")
      })}
      ${fieldCard({
        label: "签名写入字段",
        badge: state.signature.enabled ? "必填" : "可选",
        badgeType: state.signature.enabled ? "required" : "optional",
        help: "签名计算结果会写入 Structure 中的哪个变量。Basic Mode 推荐 signature。",
        format: "从 Structure 变量中选择",
        example: "signature",
        control: selectInput("signature.field", variables),
        error: state.errors["signature.field"]
      })}
    </div>
    <div class="section">
      <div class="section-title">
        <h2>签名区域 Regions</h2>
        <button class="btn" data-action="add-region">新增区域</button>
      </div>
      <p class="section-note">每一段格式是 <code>[startIndex, length]</code>。模板默认值来自样例配置：<code>[[4, 291]]</code>。</p>
      ${state.signature.regions.map((region, index) => renderRegionRow(region, index)).join("")}
      ${state.errors["signature.regions"] ? `<div class="error-text">${escapeHtml(state.errors["signature.regions"])}</div>` : ""}
    </div>
  `;
}

function renderRegionRow(region, index) {
  return `
    <div class="region-row">
      <div>
        <label class="small-label">Start Index</label>
        <input class="input" type="number" min="0" data-region="${index}" data-region-field="startIndex" value="${escapeHtml(region.startIndex)}" />
        ${state.errors[`signature.regions.${index}.startIndex`] ? `<div class="error-text">${escapeHtml(state.errors[`signature.regions.${index}.startIndex`])}</div>` : ""}
      </div>
      <div>
        <label class="small-label">Length</label>
        <input class="input" type="number" min="1" data-region="${index}" data-region-field="length" value="${escapeHtml(region.length)}" />
        ${state.errors[`signature.regions.${index}.length`] ? `<div class="error-text">${escapeHtml(state.errors[`signature.regions.${index}.length`])}</div>` : ""}
      </div>
      <div>
        <label class="small-label">写入 JSON</label>
        <input class="input" disabled value="[${escapeHtml(region.startIndex)}, ${escapeHtml(region.length)}]" />
      </div>
      <div>
        <label class="small-label">用途</label>
        <input class="input" disabled value="参与签名计算的数据段" />
      </div>
      <button class="btn danger" data-action="delete-region" data-index="${index}" ${state.signature.regions.length <= 1 ? "disabled" : ""}>删除</button>
    </div>
  `;
}

function renderMethod() {
  return `
    ${pageHead("选择签名来源", "如果你有本地私钥，选择 Offline。如果需要通过公司服务授权签名，选择 DLM。", state.run.runMode === "offline" ? "Offline" : "DLM")}
    <div class="choice-grid">
      <button class="choice-card ${state.run.runMode === "offline" ? "selected" : ""}" data-action="set-run-mode" data-value="offline">
        <div class="choice-title">Offline 本地离线签名</div>
        <div class="choice-copy">使用页面中填写的私钥和公钥在本机计算签名，不连接 DLM。</div>
      </button>
      <button class="choice-card ${state.run.runMode === "dlm" ? "selected" : ""}" data-action="set-run-mode" data-value="dlm">
        <div class="choice-title">DLM 服务器签名</div>
        <div class="choice-copy">通过 Direct、mTLS、Proxima DSA/DDA 或 AutoAuth 请求 DLM 计算签名。</div>
      </button>
    </div>
    <div class="notice warn" style="margin-top:16px">如果关闭了签名，工具仍要求选择 Offline 或 DLM。此时该选择只用于满足 exe 参数校验。</div>
  `;
}

function renderDetails() {
  if (!state.signature.enabled) {
    return `
      ${pageHead("签名参数", "当前已关闭签名生成，因此不需要填写 key 或 DLM 凭证。", "跳过")}
      <div class="notice ok">系统不会在 config.json 中生成 Signature 区域。你仍然可以进入下一步设置输出文件名。</div>
    `;
  }
  return state.run.runMode === "offline" ? renderOfflineDetails() : renderDlmDetails();
}

function renderOfflineDetails() {
  const showRsa = state.offline.publicKeyType === "rsaObject";
  const showZf = /ZF/i.test(state.offline.schemeName || "");
  return `
    ${pageHead("填写 Offline 签名参数", "这些字段会写入 config.json 的 Signature 区域，用于本地离线签名。", "Offline")}
    <div class="grid">
      ${fieldCard({
        label: "签名算法 SchemeName",
        badge: "必填",
        badgeType: "required",
        help: "选择本地签名算法。列表来自文档第 16 章以及样例中已验证的别名。",
        format: "下拉选择",
        example: "ECDSA-ZF-SECP256R1",
        control: selectInput("offline.schemeName", SCHEMES),
        error: state.errors["offline.schemeName"]
      })}
      ${fieldCard({
        label: "Public Key 格式",
        badge: "必选",
        badgeType: "required",
        help: "ECDSA/Ed25519 通常使用 Hex public key。RSA 通常使用 Exponent + Modulus 对象。",
        format: "二选一",
        example: "Hex public key",
        control: `
          <div class="toggle">
            <button data-action="set-public-key-type" data-value="hex" class="${state.offline.publicKeyType === "hex" ? "active" : ""}">Hex</button>
            <button data-action="set-public-key-type" data-value="rsaObject" class="${showRsa ? "active" : ""}">RSA Object</button>
          </div>
        `
      })}
      ${fieldCard({
        label: "KeyDataPrivate",
        badge: "必填",
        badgeType: "required",
        help: "离线签名使用的私钥。建议只在本地可信环境中填写，运行日志会避免展示该值。",
        format: "十六进制字符串",
        example: "0x46E28B...",
        control: textArea("offline.keyDataPrivate", "0x...", false, true),
        error: state.errors["offline.keyDataPrivate"],
        wide: true
      })}
      ${showRsa ? `
        ${fieldCard({
          label: "RSA Exponent",
          badge: "必填",
          badgeType: "required",
          help: "RSA 公钥指数。常见值是 65537。",
          format: "整数或字符串",
          example: "65537",
          control: textInput("offline.keyDataPublicExponent", "65537"),
          error: state.errors["offline.keyDataPublicExponent"]
        })}
        ${fieldCard({
          label: "RSA Modulus",
          badge: "必填",
          badgeType: "required",
          help: "RSA 公钥 modulus。",
          format: "十六进制字符串",
          example: "0xC5DC...",
          control: textArea("offline.keyDataPublicModulus", "0x..."),
          error: state.errors["offline.keyDataPublicModulus"]
        })}
      ` : `
        ${fieldCard({
          label: "KeyDataPublic",
          badge: "必填",
          badgeType: "required",
          help: "离线签名使用的公钥。ECDSA 和 Ed25519 样例使用十六进制字符串。",
          format: "十六进制字符串",
          example: "0xCA29AC...",
          control: textArea("offline.keyDataPublicHex", "0x..."),
          error: state.errors["offline.keyDataPublicHex"]
        })}
      `}
      ${fieldCard({
        label: "RawAdditionalDataHex",
        badge: showZf ? "建议填写" : "可选",
        badgeType: showZf ? "required" : "optional",
        help: "ZF1/ZF extension 的 additional data。文档说明该值总是 8 bytes。",
        format: "8 bytes hex",
        example: "0x50FA444400000000",
        control: textInput("offline.rawAdditionalDataHex", "0x50FA444400000000"),
        error: state.errors["offline.rawAdditionalDataHex"]
      })}
      ${fieldCard({
        label: "Sha512",
        badge: "可选",
        badgeType: "optional",
        help: "仅对 ZF1/ZF extension 有效。开启后 ZF1 extension 使用 SHA-512。",
        format: "开关",
        example: "默认关闭",
        control: checkInput("offline.sha512", "使用 SHA-512")
      })}
    </div>
  `;
}

function renderDlmDetails() {
  return `
    ${pageHead("填写 DLM 签名参数", "先填写 DLM 业务字段，再根据你手上的凭证选择连接方式。", "DLM")}
    <div class="section">
      <div class="section-title"><h2>DLM 业务字段</h2><span class="badge required">写入 Signature</span></div>
      <div class="grid">
        ${fieldCard({
          label: "ProductId",
          badge: "必填",
          badgeType: "required",
          help: "DLM REST API product id，会写入 Signature.ProductId。",
          format: "字符串",
          example: "vkfPcYKPzWypmKBMF",
          control: textInput("dlm.productId"),
          error: state.errors["dlm.productId"]
        })}
        ${fieldCard({
          label: "BuildId",
          badge: "必填",
          badgeType: "required",
          help: "用户定义的 build id，用于识别本次 DLM 请求。",
          format: "字符串",
          example: "test-cert",
          control: textInput("dlm.buildId"),
          error: state.errors["dlm.buildId"]
        })}
        ${fieldCard({
          label: "GroupId",
          badge: "必填",
          badgeType: "required",
          help: "DLM group id 或 group alias，会写入 Signature.GroupId。",
          format: "字符串",
          example: "DivE",
          control: textInput("dlm.groupId"),
          error: state.errors["dlm.groupId"]
        })}
        ${fieldCard({
          label: "Blueprint Parameters",
          badge: "高级",
          badgeType: "advanced",
          help: "JSON encoded ISS/DLM blueprint parameters。没有明确要求时可以留空。",
          format: "JSON",
          example: "{\"key\":\"value\"}",
          control: textArea("dlm.bpParams", "{ }", true)
        })}
      </div>
    </div>
    <div class="section">
      <div class="section-title"><h2>你手上有什么凭证？</h2><span class="badge required">选择连接方式</span></div>
      <div class="choice-grid">
        ${credentialCard("direct", "JWT Token", "我有用户 JWT token，使用 Direct 连接 DLM。")}
        ${credentialCard("mtls", "PEM + KEY", "我有 client certificate PEM 和 key 文件，使用 mTLS。")}
        ${credentialCard("dsa", "Proxima DSA", "我通过 Proxima DSA 使用 DLM，不需要额外 token 文件。")}
        ${credentialCard("dda", "Proxima Token", "我有 Proxima Token 文件，使用 DDA。")}
        ${credentialCard("aa", "Enrollment + Metadata", "我有 AutoAuth enrollment 和 metadata 文件。")}
      </div>
    </div>
    <div class="section">
      <div class="section-title"><h2>连接参数</h2><span class="badge required">${escapeHtml(state.dlm.type.toUpperCase())}</span></div>
      ${renderDlmConnectionFields()}
    </div>
  `;
}

function credentialCard(value, title, copy) {
  return `
    <button class="choice-card ${state.dlm.type === value ? "selected" : ""}" data-action="set-dlm-type" data-value="${value}">
      <div class="choice-title">${escapeHtml(title)}</div>
      <div class="choice-copy">${escapeHtml(copy)}</div>
    </button>
  `;
}

function renderDlmConnectionFields() {
  if (state.dlm.type === "direct") {
    return `<div class="grid">
      ${fieldCard({
        label: "Direct URI",
        badge: "必填",
        badgeType: "required",
        help: "ISS/DLM endpoint。可以选择别名，也可以选择 custom 填写完整 URI。",
        format: "下拉或 URI",
        example: "default",
        control: uriSelector("dlm.directUri", "dlm.directCustomUri", URI_OPTIONS.direct),
        error: state.errors["dlm.directUri"]
      })}
      ${fieldCard({
        label: "JWT Token",
        badge: "必填",
        badgeType: "required",
        help: "Direct 模式授权用的 JWT token。命令预览和日志中会脱敏显示。",
        format: "字符串",
        example: "eyJ...",
        control: textArea("dlm.jwt", "粘贴 JWT token", true, true),
        error: state.errors["dlm.jwt"]
      })}
      ${fieldCard({
        label: "Async",
        badge: "可选",
        badgeType: "optional",
        help: "强制使用异步 DLM 请求。exe help 将该参数列在 direct/dsa 下。",
        format: "开关",
        example: "默认关闭",
        control: checkInput("dlm.async", "启用 --async")
      })}
    </div>`;
  }
  if (state.dlm.type === "mtls") {
    return `<div class="grid">
      ${fieldCard({
        label: "mTLS URI",
        badge: "必填",
        badgeType: "required",
        help: "ISS/DLM DDA endpoint。可以选择别名，也可以填写完整 URI。",
        format: "下拉或 URI",
        example: "default",
        control: uriSelector("dlm.mtlsUri", "dlm.mtlsCustomUri", URI_OPTIONS.mtls),
        error: state.errors["dlm.mtlsUri"]
      })}
      ${fieldCard({
        label: "PEM Certificate",
        badge: "必填",
        badgeType: "required",
        help: "mTLS client certificate PEM 文件。可以上传文件，也可以填写后端机器可访问的路径。",
        format: "文件",
        example: "client.pem",
        control: fileInput("mtlsPemFile", "PEM Certificate"),
        error: state.errors["file.mtlsPemFile"]
      })}
      ${fieldCard({
        label: "Client Key",
        badge: "必填",
        badgeType: "required",
        help: "mTLS client key 文件。可以上传文件，也可以填写后端机器可访问的路径。",
        format: "文件",
        example: "client.key",
        control: fileInput("mtlsKeyFile", "Client Key"),
        error: state.errors["file.mtlsKeyFile"]
      })}
      ${fieldCard({
        label: "mTLS Chain",
        badge: "可选",
        badgeType: "optional",
        help: "额外 chain certificate 文件，用于 mutual authentication。",
        format: "文件",
        example: "chain.pem",
        control: fileInput("mtlsChainFile", "mTLS Chain")
      })}
    </div>`;
  }
  if (state.dlm.type === "dsa") {
    return `<div class="grid">
      ${fieldCard({
        label: "Proxima URI",
        badge: "可选",
        badgeType: "optional",
        help: "覆盖 Proxima endpoint。留空或 default 时使用默认 Proxima。",
        format: "下拉或 URI",
        example: "default",
        control: uriSelector("dlm.proximaUri", "dlm.proximaCustomUri", URI_OPTIONS.proxima)
      })}
      ${fieldCard({
        label: "Async",
        badge: "可选",
        badgeType: "optional",
        help: "强制使用异步 DLM 请求。",
        format: "开关",
        example: "默认关闭",
        control: checkInput("dlm.async", "启用 --async")
      })}
    </div>`;
  }
  if (state.dlm.type === "dda") {
    return `<div class="grid">
      ${fieldCard({
        label: "DDA URI",
        badge: "必填",
        badgeType: "required",
        help: "ISS/DLM DDA endpoint。可以选择别名，也可以填写完整 URI。",
        format: "下拉或 URI",
        example: "default",
        control: uriSelector("dlm.ddaUri", "dlm.ddaCustomUri", URI_OPTIONS.dda),
        error: state.errors["dlm.ddaUri"]
      })}
      ${fieldCard({
        label: "Proxima Token File",
        badge: "必填",
        badgeType: "required",
        help: "DDA 授权用的 Proxima Token 文件。可以上传文件，也可以填写路径。",
        format: "文件",
        example: "token.txt",
        control: fileInput("proximaTokenFile", "Proxima Token File"),
        error: state.errors["file.proximaTokenFile"]
      })}
      ${fieldCard({
        label: "Proxima URI",
        badge: "可选",
        badgeType: "optional",
        help: "覆盖 Proxima endpoint。",
        format: "下拉或 URI",
        example: "default",
        control: uriSelector("dlm.proximaUri", "dlm.proximaCustomUri", URI_OPTIONS.proxima)
      })}
    </div>`;
  }
  return `<div class="grid">
    ${fieldCard({
      label: "AutoAuth URI",
      badge: "必填",
      badgeType: "required",
      help: "AutoAuth endpoint。可以选择别名，也可以填写完整 URI。",
      format: "下拉或 URI",
      example: "default",
      control: uriSelector("dlm.autoAuthUri", "dlm.autoAuthCustomUri", URI_OPTIONS.aa),
      error: state.errors["dlm.autoAuthUri"]
    })}
    ${fieldCard({
      label: "Enrollment File",
      badge: "必填",
      badgeType: "required",
      help: "AutoAuth enrollment JSON 文件。可以上传文件，也可以填写路径。",
      format: "JSON 文件",
      example: "enrollment.json",
      control: fileInput("enrollmentFile", "Enrollment File"),
      error: state.errors["file.enrollmentFile"]
    })}
    ${fieldCard({
      label: "Metadata File",
      badge: "必填",
      badgeType: "required",
      help: "AutoAuth metadata JSON 文件。可以上传文件，也可以填写路径。",
      format: "JSON 文件",
      example: "metadata.json",
      control: fileInput("metadataFile", "Metadata File"),
      error: state.errors["file.metadataFile"]
    })}
  </div>`;
}

function renderOutput() {
  return `
    ${pageHead("输出设置", "设置输出文件名和通用运行选项。后端会把生成的 config.json 和证书输出放在独立 job 目录。", "最后设置")}
    <div class="grid">
      ${fieldCard({
        label: "Output File Name",
        badge: "必填",
        badgeType: "required",
        help: "生成的 certificate 文件名。建议使用 .cert 后缀。",
        format: "文件名",
        example: "cert-0z600851-00000007.cert",
        control: textInput("run.outputFileName", "output.cert"),
        error: state.errors["run.outputFileName"]
      })}
      ${fieldCard({
        label: "No Colors",
        badge: "建议开启",
        badgeType: "ok",
        help: "禁用控制台颜色，前端日志更干净。",
        format: "开关",
        example: "默认开启",
        control: checkInput("run.noColors", "启用 --no_colors")
      })}
      ${fieldCard({
        label: "Verbose",
        badge: "可选",
        badgeType: "optional",
        help: "显示更多工具日志。排查问题时建议开启。",
        format: "开关",
        example: "默认关闭",
        control: checkInput("run.verbose", "启用 --verbose")
      })}
      ${fieldCard({
        label: "Hash Algorithm",
        badge: "可选",
        badgeType: "optional",
        help: "CsiCertificateTool 的 --hash 参数。文档给出的默认值是 SHA256。",
        format: "下拉",
        example: "SHA256",
        control: selectInput("run.hashAlgorithm", ["NONE", "SHA256", "SHA512"])
      })}
      ${state.run.runMode === "offline" ? fieldCard({
        label: "Disable ZF1",
        badge: "高级",
        badgeType: "advanced",
        help: "禁用 ZF1 extension。只有 offline module 有意义。",
        format: "开关",
        example: "默认关闭",
        control: checkInput("run.disableZf1", "启用 --no_zf1")
      }) : fieldCard({
        label: "HTTP Proxy",
        badge: "可选",
        badgeType: "optional",
        help: "DLM 请求使用的 HTTP proxy。",
        format: "URI",
        example: "http://cloudproxy.zf-world.com:8080",
        control: textInput("dlm.httpProxy", "http://...")
      })}
    </div>
  `;
}

function renderReview() {
  const config = buildConfig();
  const command = buildCommandPreview();
  return `
    ${pageHead("确认并生成", "请检查摘要、生成的 config.json 和即将执行的命令。确认无误后点击生成证书。", "Ready")}
    <div class="summary-grid">
      ${summaryCard("运行模式", state.run.runMode.toUpperCase())}
      ${summaryCard("输出文件", state.run.outputFileName || "output.cert")}
      ${summaryCard("签名", state.signature.enabled ? "启用" : "跳过")}
      ${summaryCard("模板", state.templateMode === "advanced" ? "高级自定义结构" : "内置证书模板")}
      ${summaryCard("签名字段", state.signature.enabled ? state.signature.field : "无")}
      ${summaryCard("签名来源", state.run.runMode === "offline" ? state.offline.schemeName : state.dlm.type.toUpperCase())}
    </div>
    <div class="section">
      <div class="section-title"><h2>生成的 config.json</h2><span class="badge ok">自动生成</span></div>
      <pre class="code-panel">${escapeHtml(JSON.stringify(config, null, 2))}</pre>
    </div>
    <div class="section">
      <div class="section-title"><h2>命令预览</h2><span class="badge optional">敏感信息已脱敏</span></div>
      <pre class="code-panel">${escapeHtml(command)}</pre>
    </div>
  `;
}

function summaryCard(label, value) {
  return `
    <div class="summary-card">
      <div class="summary-label">${escapeHtml(label)}</div>
      <div class="summary-value">${escapeHtml(value)}</div>
    </div>
  `;
}

function renderResult() {
  const result = state.result;
  if (!result) {
    return `
      ${pageHead("运行结果", "证书生成结果会显示在这里。", "等待运行")}
      <div class="notice">还没有运行任务。请返回确认页点击生成证书。</div>
    `;
  }
  const ok = result.exitCode === 0;
  const message = exitCodeMessage(result.exitCode);
  return `
    ${pageHead("运行结果", "查看 exe 返回码、日志，并下载生成的证书或 config.json。", ok ? "成功" : "失败")}
    <div class="summary-card">
      <div class="result-title"><span class="result-dot ${ok ? "ok" : "fail"}"></span>${escapeHtml(message.title)}</div>
      <p class="page-copy">${escapeHtml(message.copy)}</p>
      ${result.downloadsDir ? `
        <div class="notice ok">
          已自动保存到本机 Downloads 目录：<br />
          <strong>${escapeHtml(result.downloadsDir)}</strong>
          ${result.savedOutputPath ? `<br />证书：<strong>${escapeHtml(result.savedOutputPath)}</strong>` : ""}
          ${result.savedConfigPath ? `<br />JSON：<strong>${escapeHtml(result.savedConfigPath)}</strong>` : ""}
        </div>
      ` : ""}
      <div class="button-group">
        ${result.outputUrl ? `<a class="btn primary" href="${escapeHtml(result.outputUrl)}" download>浏览器下载证书</a>` : ""}
        ${result.configUrl ? `<a class="btn" href="${escapeHtml(result.configUrl)}" download>浏览器下载生成的 JSON</a>` : ""}
        ${result.downloadsDir ? `<button class="btn" data-action="open-downloads">打开本机 Downloads 文件夹</button>` : ""}
      </div>
    </div>
    <div class="section">
      <div class="section-title"><h2>Exit Code</h2><span class="badge ${ok ? "ok" : "required"}">${escapeHtml(String(result.exitCode))}</span></div>
      <pre class="code-panel">${escapeHtml(result.command || "")}</pre>
    </div>
    <div class="section">
      <div class="section-title"><h2>工具日志</h2><span class="badge optional">stdout / stderr</span></div>
      <pre class="code-panel">${escapeHtml((result.stdout || "") + (result.stderr ? `\n--- STDERR ---\n${result.stderr}` : ""))}</pre>
    </div>
  `;
}

function exitCodeMessage(code) {
  const map = {
    0: ["证书生成成功", "CsiCertificateTool.exe 返回 0，输出证书文件已生成。"],
    1: ["配置加载失败", "工具无法加载 generated-config.json，请检查表单字段和生成的 JSON。"],
    2: ["签名计算失败", "请检查签名算法、key、DLM 凭证或签名区域。"],
    3: ["证书生成失败", "请检查证书结构、Data 字段和输出路径。"],
    9: ["授权失败", "请检查 DLM token、证书、enrollment、metadata 或网络权限。"],
    "-4": ["输入参数无效", "请检查必填项以及 DLM/offline 参数组合。"],
    "-1638": ["未定义错误", "工具返回未定义错误，请查看详细日志。"]
  };
  const item = map[String(code)] || ["运行结束", `工具返回 exit code ${code}。`];
  return { title: item[0], copy: item[1] };
}

function renderBody() {
  if (state.step === 0) return renderStart();
  if (state.step === 1) return renderData();
  if (state.step === 2) return renderSignature();
  if (state.step === 3) return renderMethod();
  if (state.step === 4) return renderDetails();
  if (state.step === 5) return renderOutput();
  if (state.step === 6) return renderReview();
  return renderResult();
}

function renderButtons() {
  const atStart = state.step === 0;
  const atReview = state.step === 6;
  const atResult = state.step === 7;
  return `
    <div class="button-row">
      <div class="button-group">
        <button class="btn" data-action="back" ${atStart || state.busy ? "disabled" : ""}>上一步</button>
        <button class="btn ghost" data-action="reset" ${state.busy ? "disabled" : ""}>重置</button>
      </div>
      <div class="button-group">
        ${atReview ? `<button class="btn primary" data-action="run" ${state.busy ? "disabled" : ""}>${state.busy ? "生成中..." : "生成证书"}</button>` : ""}
        ${!atReview && !atResult ? `<button class="btn primary" data-action="next" ${state.busy ? "disabled" : ""}>下一步</button>` : ""}
        ${atResult ? `<button class="btn primary" data-action="go-review">返回确认页</button>` : ""}
      </div>
    </div>
  `;
}

function render() {
  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <div class="brand">
          <div class="brand-title">CSI Certificate Wizard</div>
          <div class="brand-subtitle">表单生成 config.json，并调用 CsiCertificateTool.exe 输出证书</div>
        </div>
        <div class="status-pill">CsiCertificateTool 2.4.0</div>
      </header>
      <div class="workspace">
        <aside class="sidebar">
          <div class="progress-list">${stepHtml()}</div>
        </aside>
        <main class="main">
          ${renderBody()}
          ${renderButtons()}
        </main>
      </div>
    </div>
  `;
  bindEvents();
}

function bindEvents() {
  app.querySelectorAll("[data-bind]").forEach((element) => {
    const path = element.dataset.bind;
    const eventName = element.type === "checkbox" || element.tagName === "SELECT" ? "change" : "input";
    element.addEventListener(eventName, () => {
      const value = element.type === "checkbox" ? element.checked : element.value;
      setAt(path, value);
      if (path === "signature.enabled" && !value) state.signature.field = "";
      if (path === "signature.enabled" && value && !state.signature.field) state.signature.field = "signature";
      render();
    });
  });

  app.querySelectorAll("[data-path-field]").forEach((element) => {
    element.addEventListener("input", () => {
      state.paths[element.dataset.pathField] = element.value;
    });
  });

  app.querySelectorAll("[data-file]").forEach((element) => {
    element.addEventListener("change", async () => {
      const file = element.files[0];
      if (!file) return;
      const contentBase64 = await readFileBase64(file);
      state.uploadedFiles[element.dataset.file] = { name: file.name, contentBase64 };
      render();
    });
  });

  const importInput = app.querySelector("[data-import-json]");
  if (importInput) {
    importInput.addEventListener("change", async () => {
      const file = importInput.files[0];
      if (!file) return;
      const text = await file.text();
      try {
        applyLoadedConfig(JSON.parse(text));
      } catch (error) {
        state.errors.importJson = error.message;
      }
      render();
    });
  }

  app.querySelectorAll("[data-node]").forEach((element) => {
    element.addEventListener("input", () => updateNodeField(element));
    element.addEventListener("change", () => updateNodeField(element));
  });

  app.querySelectorAll("[data-region]").forEach((element) => {
    element.addEventListener("input", () => {
      const index = Number(element.dataset.region);
      state.signature.regions[index][element.dataset.regionField] = element.value;
    });
  });

  app.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.preventDefault();
      handleAction(button.dataset.action, button.dataset);
    });
  });
}

function updateNodeField(element) {
  const node = state.nodes.find((item) => item.id === element.dataset.node);
  if (!node) return;
  const field = element.dataset.nodeField;
  node[field] = field === "tag" || field === "order" ? Number(element.value) : element.value || null;
  if (field === "asn1Type" && node.asn1Type === "Sequence") node.variableName = "";
  render();
}

function handleAction(action, dataset) {
  if (action === "set-template") {
    state.templateMode = dataset.value;
    if (dataset.value === "basic") {
      state.nodes = sampleNodes();
      state.signature.field = "signature";
    }
    render();
    return;
  }
  if (action === "load-sample") {
    loadSelectedSample();
    return;
  }
  if (action === "set-run-mode") {
    state.run.runMode = dataset.value;
    render();
    return;
  }
  if (action === "set-public-key-type") {
    state.offline.publicKeyType = dataset.value;
    render();
    return;
  }
  if (action === "set-dlm-type") {
    state.dlm.type = dataset.value;
    render();
    return;
  }
  if (action === "add-region") {
    state.signature.regions.push({ startIndex: 0, length: 1 });
    render();
    return;
  }
  if (action === "delete-region") {
    state.signature.regions.splice(Number(dataset.index), 1);
    render();
    return;
  }
  if (action === "add-node") {
    const id = `n${Date.now()}`;
    const firstSequence = sequenceNodes()[0];
    state.nodes.push({
      id,
      parentId: firstSequence ? firstSequence.id : null,
      order: state.nodes.length + 1,
      asn1Type: dataset.kind === "sequence" ? "Sequence" : "OctetString",
      asn1Class: "Application",
      tag: 1,
      variableName: dataset.kind === "sequence" ? "" : `field${state.nodes.length + 1}`
    });
    render();
    return;
  }
  if (action === "delete-node") {
    const id = dataset.id;
    state.nodes = state.nodes.filter((node) => node.id !== id && node.parentId !== id);
    render();
    return;
  }
  if (action === "next") {
    if (validateStep()) {
      state.step = Math.min(state.step + 1, STEPS.length - 1);
      state.errors = {};
    }
    render();
    return;
  }
  if (action === "back") {
    state.step = Math.max(state.step - 1, 0);
    state.errors = {};
    render();
    return;
  }
  if (action === "go-review") {
    state.step = 6;
    render();
    return;
  }
  if (action === "reset") {
    resetState();
    render();
    return;
  }
  if (action === "run") {
    runTool();
  }
  if (action === "open-downloads") {
    openDownloadsFolder();
  }
}

function resetState() {
  const fresh = {
    step: 0,
    templateMode: "basic",
    nodes: sampleNodes(),
    data: {
      version: "0x020000",
      certificateSerialNumber: "00000007",
      subjectId: "0z600851",
      publicKeyModulo: "",
      publicKeyExponent: "0x00010001"
    },
    signature: { enabled: true, field: "signature", regions: [{ startIndex: 4, length: 291 }] },
    run: { runMode: "offline", outputFileName: "output.cert", verbose: false, noColors: true, hashAlgorithm: "SHA256", disableZf1: false },
    offline: { schemeName: "ECDSA-ZF-SECP256R1", keyDataPrivate: "", publicKeyType: "hex", keyDataPublicHex: "", keyDataPublicExponent: "65537", keyDataPublicModulus: "", rawAdditionalDataHex: "0x50FA444400000000", sha512: false },
    dlm: { type: "dsa", credentialType: "dsa", productId: "", buildId: "", groupId: "", ecuId: "", projectId: "", componentId: "", bpParams: "", directUri: "default", directCustomUri: "", jwt: "", mtlsUri: "default", mtlsCustomUri: "", ddaUri: "default", ddaCustomUri: "", autoAuthUri: "default", autoAuthCustomUri: "", proximaUri: "default", proximaCustomUri: "", httpProxy: "", async: false },
    paths: {},
    uploadedFiles: {},
    samples: state.samples || [],
    selectedSample: state.selectedSample || "",
    sampleDir: state.sampleDir || "",
    errors: {},
    result: null,
    busy: false
  };
  Object.keys(state).forEach((key) => delete state[key]);
  Object.assign(state, fresh);
}

function readFileBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1]);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

function normalizeType(type) {
  const upper = String(type || "").toUpperCase();
  if (upper.includes("SEQUENCE")) return "Sequence";
  if (upper.includes("OCTET")) return "OctetString";
  if (upper.includes("UTF8") || upper.includes("STRING")) return "UTF8String";
  if (upper.includes("INT")) return "Integer";
  if (upper.includes("BOOL")) return "Boolean";
  return "OctetString";
}

function normalizeClass(cls) {
  const upper = String(cls || "").toUpperCase();
  if (upper.includes("CONTEXT")) return "ContextSpecific";
  if (upper.includes("PRIVATE")) return "Private";
  if (upper.includes("UNIVERSAL")) return "Universal";
  return "Application";
}

function importConfig(config) {
  if (!config.Structure || !config.Data) throw new Error("JSON 必须包含 Structure 和 Data。");
  const nodes = [];
  let counter = 1;
  function walk(obj, parentId) {
    Object.entries(obj).forEach(([key, value], index) => {
      const [type, cls, tag] = key.split(":");
      const id = `n${counter++}`;
      const isSequence = typeof value === "object" && value !== null && !Array.isArray(value);
      nodes.push({
        id,
        parentId,
        order: index + 1,
        asn1Type: isSequence ? "Sequence" : normalizeType(type),
        asn1Class: normalizeClass(cls),
        tag: Number(tag) || 0,
        variableName: isSequence ? "" : String(value)
      });
      if (isSequence) walk(value, id);
    });
  }
  walk(config.Structure, null);
  state.nodes = nodes.length ? nodes : sampleNodes();
  state.data = { ...config.Data };
  if (config.Signature) {
    state.signature.enabled = true;
    state.signature.field = config.Signature.Field || "signature";
    state.signature.regions = Array.isArray(config.Signature.Regions)
      ? config.Signature.Regions.map((item) => ({ startIndex: item[0], length: item[1] }))
      : [{ startIndex: 4, length: 291 }];
    if (config.Signature.SchemeName) {
      state.run.runMode = "offline";
      state.offline.schemeName = config.Signature.SchemeName;
      state.offline.keyDataPrivate = config.Signature.KeyDataPrivate || "";
      if (typeof config.Signature.KeyDataPublic === "object") {
        state.offline.publicKeyType = "rsaObject";
        state.offline.keyDataPublicExponent = config.Signature.KeyDataPublic.Exponent || "";
        state.offline.keyDataPublicModulus = config.Signature.KeyDataPublic.Modulus || "";
      } else {
        state.offline.publicKeyType = "hex";
        state.offline.keyDataPublicHex = config.Signature.KeyDataPublic || "";
      }
      state.offline.rawAdditionalDataHex = config.Signature.RawAdditionalDataHex || "";
      state.offline.sha512 = Boolean(config.Signature.Sha512);
    } else {
      state.run.runMode = "dlm";
      state.dlm.productId = config.Signature.ProductId || "";
      state.dlm.buildId = config.Signature.BuildId || "";
      state.dlm.groupId = config.Signature.GroupId || "";
      state.dlm.ecuId = config.Signature.EcuId || "";
      state.dlm.projectId = config.Signature.ProjectId || "";
      state.dlm.componentId = config.Signature.ComponentId || "";
      state.dlm.bpParams = config.Signature.BpParams ? JSON.stringify(config.Signature.BpParams, null, 2) : "";
    }
  } else {
    state.signature.enabled = false;
  }
}

function structureLooksLikeBasicTemplate() {
  const names = variableNodes().map((node) => node.variableName);
  return ["version", "certificateSerialNumber", "subjectId", "publicKeyModulo", "publicKeyExponent", "signature"]
    .every((name) => names.includes(name));
}

function applyLoadedConfig(config) {
  importConfig(config);
  state.templateMode = structureLooksLikeBasicTemplate() ? "basic" : "advanced";
  if (!state.run.outputFileName || state.run.outputFileName === "output.cert") {
    const subject = state.data.subjectId || "subject";
    const serial = state.data.certificateSerialNumber || "certificate";
    state.run.outputFileName = `cert-${subject}-${serial}.cert`;
  }
  state.step = 1;
  state.errors = {};
}

async function loadSamples() {
  try {
    const response = await fetch("/api/samples");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "样例列表读取失败。");
    state.samples = payload.files || [];
    state.sampleDir = payload.sampleDir || "";
    if (!state.selectedSample && state.samples.length) {
      const preferred = state.samples.find((sample) => sample.name === "offline-ecdsa-zf1-secp256r1.json");
      state.selectedSample = (preferred || state.samples[0]).name;
    }
  } catch (error) {
    state.errors.sample = error.message;
  }
  render();
}

async function loadSelectedSample() {
  if (!state.selectedSample) return;
  try {
    const response = await fetch(`/api/samples/${encodeURIComponent(state.selectedSample)}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "样例加载失败。");
    applyLoadedConfig(payload.config);
  } catch (error) {
    state.errors.sample = error.message;
  }
  render();
}

function payloadForRun() {
  const dlmConnection = {
    ...state.dlm,
    directUri: currentUri("dlm.directUri", "dlm.directCustomUri"),
    mtlsUri: currentUri("dlm.mtlsUri", "dlm.mtlsCustomUri"),
    ddaUri: currentUri("dlm.ddaUri", "dlm.ddaCustomUri"),
    autoAuthUri: currentUri("dlm.autoAuthUri", "dlm.autoAuthCustomUri"),
    proximaUri: currentUri("dlm.proximaUri", "dlm.proximaCustomUri")
  };
  return {
    outputFileName: state.run.outputFileName,
    config: buildConfig(),
    form: {
      run: state.run,
      signature: state.signature,
      offline: state.offline,
      dlmConnection
    },
    uploadedFiles: state.uploadedFiles,
    paths: state.paths
  };
}

async function runTool() {
  if (!validateStep(6)) return;
  state.busy = true;
  state.result = null;
  render();
  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payloadForRun())
    });
    state.result = await response.json();
    state.step = 7;
  } catch (error) {
    state.result = {
      exitCode: null,
      command: buildCommandPreview(),
      stdout: "",
      stderr: error.message,
      outputUrl: null,
      configUrl: null
    };
    state.step = 7;
  } finally {
    state.busy = false;
    render();
  }
}

async function openDownloadsFolder() {
  try {
    await fetch("/api/open-downloads", { method: "POST" });
  } catch (error) {
    state.result = {
      ...(state.result || {}),
      stderr: `${state.result?.stderr || ""}\nOpen Downloads failed: ${error.message}`
    };
    render();
  }
}

render();
loadSamples();
