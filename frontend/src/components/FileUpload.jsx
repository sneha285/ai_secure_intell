import React from "react";

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Failed to read file"));
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.readAsDataURL(file);
  });
}

function fileToText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Failed to read file as text"));
    reader.onload = () => resolve(String(reader.result || ""));
    reader.readAsText(file);
  });
}

export default function FileUpload({ onSelected }) {
  const [dragOver, setDragOver] = React.useState(false);

  async function handleFile(file) {
    const ext = file.name?.toLowerCase().split(".").pop() || "";
    const wantsTextPreview = ext === "log" || ext === "txt" || ext === "sql";

    const contentText = wantsTextPreview ? await fileToText(file).catch(() => "") : "";
    const contentBase64 = await fileToBase64(file);

    onSelected?.({
      file,
      filename: file.name,
      contentText,
      contentBase64,
      ext,
    });
  }

  function onDrop(e) {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file).catch(() => {});
  }

  function onPick(e) {
    const file = e.target.files?.[0];
    if (file) handleFile(file).catch(() => {});
  }

  return (
    <div
      className={`dropzone ${dragOver ? "dropzone--over" : ""}`}
      onDragEnter={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={(e) => {
        e.preventDefault();
        setDragOver(false);
      }}
      onDrop={onDrop}
    >
      <div className="dropzone__title">Drag & drop a log file (.log/.txt)</div>
      <div className="dropzone__hint">or</div>
      <label className="dropzone__button">
        Choose file
        <input
          type="file"
          accept=".log,.txt,.sql,.pdf,.doc,.docx,.json,.xml"
          onChange={onPick}
          style={{ display: "none" }}
        />
      </label>
    </div>
  );
}

