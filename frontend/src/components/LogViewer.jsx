import React from "react";

function riskRank(level) {
  switch (level) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    default:
      return 1;
  }
}

export default function LogViewer({ content, findings }) {
  const lines = (content || "").split(/\r?\n/);
  const lineFindings = React.useMemo(() => {
    const map = new Map();
    (findings || []).forEach((f) => {
      if (typeof f.line_number !== "number") return;
      const ln = f.line_number;
      const arr = map.get(ln) || [];
      arr.push(f);
      map.set(ln, arr);
    });
    return map;
  }, [findings]);

  const truncated = lines.length > 5000;
  const viewLines = truncated ? lines.slice(0, 5000) : lines;

  return (
    <div className="logViewer">
      <div className="logViewer__title">Log / Content Viewer</div>
      {viewLines.length === 0 ? <div className="muted">No content to display.</div> : null}
      {truncated ? <div className="muted">Showing first 5000 lines for performance.</div> : null}

      <div className="logViewer__lines">
        {viewLines.map((line, idx) => {
          const lnum = idx;
          const f = lineFindings.get(lnum) || [];
          if (!f.length) {
            return (
              <div className="logLine" key={idx}>
                <span className="logLine__ln">{idx + 1}</span>
                <span className="logLine__text">{line}</span>
              </div>
            );
          }

          const best = f
            .map((x) => x.risk_level)
            .sort((a, b) => riskRank(b) - riskRank(a))[0];
          return (
            <div className={`logLine logLine--${best}`} key={idx} title={f.map((x) => x.title).join(" | ")}>
              <span className="logLine__ln">{idx + 1}</span>
              <span className="logLine__text">{line}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

