import React from "react";

export default function InsightsPanel({ summary, insights }) {
  return (
    <div className="panel">
      <div className="panel__title">AI Insights</div>
      {summary ? <div className="panel__summary">{summary}</div> : null}
      <div className="insights">
        {(insights || []).length === 0 ? (
          <div className="muted">No insights available.</div>
        ) : (
          insights.map((item, idx) => (
            <div className="insight" key={`${idx}-${item.slice(0, 20)}`}>
              {item}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

