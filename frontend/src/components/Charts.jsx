/**
 * Charts.jsx — DonutChart + BarChart
 */

export function BarChart({ data, height = 160 }) {
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 8, height, padding: "0 4px" }}>
      {data.map((d, i) => (
        <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: d.color || "#ccc" }}>{d.value}</div>
          <div style={{
            width: "100%", borderRadius: "4px 4px 0 0",
            height: `${(d.value / max) * (height - 40)}px`,
            background: d.color || "#555",
            transition: "height 0.5s ease-out",
            minHeight: 2,
          }} />
          <div style={{ fontSize: 9, color: "#888", textAlign: "center" }}>{d.label}</div>
        </div>
      ))}
    </div>
  );
}

export function DonutChart({ data, size = 140 }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  let cumulative = 0;
  const segments = data.map(d => {
    const start = cumulative;
    cumulative += (d.value / total) * 360;
    return { ...d, start, end: cumulative };
  });
  const gradientParts = segments.map(s => `${s.color} ${s.start}deg ${s.end}deg`).join(", ");
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <div style={{
        width: size, height: size, borderRadius: "50%",
        background: `conic-gradient(${gradientParts})`,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        <div style={{ width: size * 0.6, height: size * 0.6, borderRadius: "50%", background: "#09090f", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ fontSize: 20, fontWeight: 800, color: "#fff" }}>{total}</span>
        </div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {data.map((d, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11 }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color }} />
            <span style={{ color: "#aaa" }}>{d.label}</span>
            <span style={{ color: d.color, fontWeight: 700 }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
