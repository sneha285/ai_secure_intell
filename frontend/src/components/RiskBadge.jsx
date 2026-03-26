import React from "react";

function colorForRisk(riskLevel) {
  switch (riskLevel) {
    case "critical":
      return { bg: "#b71c1c", fg: "white" };
    case "high":
      return { bg: "#d84315", fg: "white" };
    case "medium":
      return { bg: "#f9a825", fg: "#1a1a1a" };
    default:
      return { bg: "#2e7d32", fg: "white" };
  }
}

export default function RiskBadge({ riskScore, riskLevel, action }) {
  const c = colorForRisk(riskLevel);
  return (
    <div className="riskBadge" style={{ background: c.bg, color: c.fg }}>
      <div className="riskBadge__top">
        <span className="riskBadge__label">Risk</span>
        <span className="riskBadge__value">{riskLevel}</span>
      </div>
      <div className="riskBadge__bottom">
        <span className="riskBadge__score">score: {Number(riskScore).toFixed(1)}</span>
        <span className="riskBadge__action">action: {action}</span>
      </div>
    </div>
  );
}

