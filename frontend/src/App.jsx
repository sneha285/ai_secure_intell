import React from "react";
import { analyze } from "./api/analyze.js";
import FileUpload from "./components/FileUpload.jsx";
import LogViewer from "./components/LogViewer.jsx";
import InsightsPanel from "./components/InsightsPanel.jsx";
import RiskBadge from "./components/RiskBadge.jsx";

export default function App() {
  const [mode, setMode] = React.useState("text"); // "text" | "file"
  const [inputType, setInputType] = React.useState("log"); // backend input_type for text mode
  const [contentText, setContentText] = React.useState("");

  const [fileMeta, setFileMeta] = React.useState(null); // { filename, contentBase64 }

  const [options, setOptions] = React.useState({
    mask: true,
    block_high_risk: true,
    log_analysis: true,
    enable_ai_insights: false,
  });

  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const [result, setResult] = React.useState(null);

  async function onAnalyze() {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      if (mode === "file") {
        if (!fileMeta?.filename) throw new Error("No file selected");
        const payload = {
          input_type: "file",
          content: fileMeta.contentBase64,
          filename: fileMeta.filename,
          options: options,
        };
        const data = await analyze(payload);
        setResult(data);
      } else {
        const payload = {
          input_type: inputType,
          content: contentText,
          options: options,
        };
        const data = await analyze(payload);
        setResult(data);
      }
    } catch (e) {
      setError(e?.message || "Request failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <div className="header">
        <div className="header__title">AI Secure Data Intelligence Platform</div>
        <div className="header__subtitle">Security analysis: regex + log analyzer + optional AI insights</div>
      </div>

      <div className="grid">
        <div className="left">
          <div className="section">
            <div className="section__title">Input</div>
            {mode === "file" ? (
              <FileUpload
                onSelected={({ filename, contentText: textPreview, contentBase64 }) => {
                  setMode("file");
                  setFileMeta({ filename, contentBase64 });
                  setContentText(textPreview || "");
                  setInputType("log");
                }}
              />
            ) : null}

            {mode === "text" ? (
              <>
                <div className="row">
                  <label className="label">Input type</label>
                  <select className="select" value={inputType} onChange={(e) => setInputType(e.target.value)}>
                    <option value="text">text</option>
                    <option value="log">log</option>
                    <option value="sql">sql</option>
                    <option value="chat">chat</option>
                  </select>
                </div>
                <textarea
                  className="textarea"
                  value={contentText}
                  onChange={(e) => setContentText(e.target.value)}
                  placeholder="Paste text, SQL, chat, or logs here..."
                />
              </>
            ) : null}

            <div className="row">
              <button
                className={mode === "text" ? "btn btn--primary" : "btn"}
                onClick={() => {
                  setMode("text");
                  setFileMeta(null);
                }}
              >
                Text Mode
              </button>
              <button
                className={mode === "file" ? "btn btn--primary" : "btn"}
                onClick={() => {
                  setMode("file");
                  setResult(null);
                  setError("");
                }}
              >
                File Mode
              </button>
            </div>
          </div>

          <div className="section">
            <div className="section__title">Options</div>
            <div className="options">
              <label className="check">
                <input
                  type="checkbox"
                  checked={options.mask}
                  onChange={(e) => setOptions((o) => ({ ...o, mask: e.target.checked }))}
                />
                Mask
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={options.block_high_risk}
                  onChange={(e) => setOptions((o) => ({ ...o, block_high_risk: e.target.checked }))}
                />
                Block high/critical
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={options.log_analysis}
                  onChange={(e) => setOptions((o) => ({ ...o, log_analysis: e.target.checked }))}
                />
                Log analyzer
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={options.enable_ai_insights}
                  onChange={(e) => setOptions((o) => ({ ...o, enable_ai_insights: e.target.checked }))}
                />
                Enable AI insights (requires backend `OPENAI_API_KEY`)
              </label>
            </div>
          </div>

          <div className="section">
            <div className="section__title">Run Analysis</div>
            <button className="btn btn--primary" onClick={onAnalyze} disabled={loading}>
              {loading ? "Analyzing..." : "POST /analyze"}
            </button>
            {error ? <div className="error">{error}</div> : null}
          </div>
        </div>

        <div className="right">
          {result ? (
            <>
              <RiskBadge riskScore={result.risk_score} riskLevel={result.risk_level} action={result.action} />
              <InsightsPanel summary={result.summary} insights={result.insights} />
              <LogViewer content={contentText} findings={result.findings} />
            </>
          ) : (
            <div className="muted">Run an analysis to see findings, risk, and insights.</div>
          )}
        </div>
      </div>
    </div>
  );
}

