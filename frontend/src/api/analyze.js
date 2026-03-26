const getApiBaseUrl = () => {
  // Vite uses import.meta.env.
  return import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
};

export async function analyze(payload) {
  const res = await fetch(`${getApiBaseUrl()}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = data?.detail || `HTTP ${res.status}`;
    throw new Error(detail);
  }
  return data;
}

