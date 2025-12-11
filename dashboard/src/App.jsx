import React, { useEffect, useState } from "react";
import { sampleFrames } from "./sampleData";

const FrameTable = ({ frames }) => (
  <table className="table">
    <thead>
      <tr>
        <th>ID</th>
        <th>DLC</th>
        <th>Data</th>
        <th>Label</th>
      </tr>
    </thead>
    <tbody>
      {frames.map((f, idx) => (
        <tr key={idx} className={f.label !== "normal" ? "alert" : ""}>
          <td>{`0x${f.message_id.toString(16)}`}</td>
          <td>{f.dlc}</td>
          <td>{f.data.join(", ")}</td>
          <td>{f.label}</td>
        </tr>
      ))}
    </tbody>
  </table>
);

const Metrics = ({ alerts }) => (
  <div className="card">
    <h3>Intrusion Alerts</h3>
    <ul>
      {alerts.map((a, idx) => (
        <li key={idx}>{`${a.frame.message_id} -> ${a.reason}`}</li>
      ))}
    </ul>
  </div>
);

export default function App() {
  const [frames, setFrames] = useState(sampleFrames);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    // In production this would subscribe to a WebSocket stream.
    const attackAlerts = frames
      .filter((f) => f.label !== "normal")
      .map((f) => ({ frame: f, reason: "synthetic-demo" }));
    setAlerts(attackAlerts);
  }, [frames]);

  return (
    <div className="container">
      <header>
        <h1>Automotive CAN IDS Dashboard</h1>
        <p>Visualises synthetic CAN frames, anomaly scores, and firmware risk.</p>
      </header>
      <section className="grid">
        <div>
          <h2>Live CAN Frames (Synthetic)</h2>
          <FrameTable frames={frames} />
        </div>
        <Metrics alerts={alerts} />
      </section>
      <footer>Safe demo. No real vehicle interaction.</footer>
    </div>
  );
}
