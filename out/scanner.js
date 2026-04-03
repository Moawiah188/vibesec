"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanFile = scanFile;
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
// Map Semgrep severity strings to VS Code diagnostic levels
function mapSeverity(sev) {
    switch (sev.toUpperCase()) {
        case "ERROR":
            return "error";
        case "WARNING":
            return "warning";
        default:
            return "info";
    }
}
// Pick a Semgrep config based on the file extension
function configForFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const langConfigs = {
        ".py": ["r/python.lang.security"],
        ".js": ["r/javascript.lang.security"],
        ".ts": ["r/typescript.lang.security"],
        ".jsx": ["r/javascript.lang.security"],
        ".tsx": ["r/typescript.lang.security"],
        ".java": ["r/java.lang.security"],
        ".go": ["r/go.lang.security"],
        ".rb": ["r/ruby.lang.security"],
        ".php": ["r/php.lang.security"],
    };
    return langConfigs[ext] || ["r/generic.secrets"];
}
// Parse Semgrep JSON output into our internal Finding model
function parseSemgrepOutput(json) {
    const data = JSON.parse(json);
    const results = data.results || [];
    return results.map((r) => ({
        ruleId: r.check_id || "unknown",
        message: r.extra?.message || "Security issue detected",
        severity: mapSeverity(r.extra?.severity || "WARNING"),
        filePath: r.path,
        startLine: (r.start?.line ?? 1) - 1, // Semgrep is 1-based, VS Code is 0-based
        startCol: (r.start?.col ?? 1) - 1,
        endLine: (r.end?.line ?? 1) - 1,
        endCol: (r.end?.col ?? 1) - 1,
        snippet: r.extra?.lines || "",
    }));
}
// Run Semgrep on a single file and return parsed findings
function scanFile(filePath) {
    return new Promise((resolve, reject) => {
        const configs = configForFile(filePath);
        const configArgs = configs.flatMap((c) => ["--config", c]);
        (0, child_process_1.execFile)("semgrep", ["scan", "--json", ...configArgs, filePath], {
            maxBuffer: 10 * 1024 * 1024,
            timeout: 120000,
            env: { ...process.env, PYTHONIOENCODING: "utf-8" },
        }, (error, stdout, _stderr) => {
            // Semgrep exits with code 1 when it finds issues — that's normal
            if (error && error.code !== 1 && !stdout) {
                reject(new Error(`Semgrep failed: ${error.message}`));
                return;
            }
            try {
                const findings = parseSemgrepOutput(stdout);
                resolve(findings);
            }
            catch (parseErr) {
                reject(new Error(`Failed to parse Semgrep output: ${parseErr.message}`));
            }
        });
    });
}
//# sourceMappingURL=scanner.js.map