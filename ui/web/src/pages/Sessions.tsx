import { useEffect, useState } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import { get, Session, fmtDuration } from "../api";

const fmtBytes = (n?: number) => {
  if (n === undefined || !Number.isFinite(n)) return "—";
  let v = n;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
};

export default function SessionsPage() {
  const [rows, setRows] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    get<Session[]>("/api/sessions")
      .then((d) => {
        setRows(d);
        setErr(null);
      })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Active RADIUS accounting sessions (live), refreshed every 10s. A session appears on Accounting-Start and is removed on Accounting-Stop or after the inactivity timeout."
          actions={<Button iconName="refresh" onClick={load} loading={loading} />}
        >
          Sessions
        </Header>
      }
    >
      <Table
        variant="container"
        header={<Header counter={`(${rows.length})`}>Active sessions</Header>}
        loading={loading && rows.length === 0}
        loadingText="Loading sessions…"
        columnDefinitions={[
          { id: "user", header: "User", cell: (s) => s.username || "—" },
          { id: "nas", header: "NAS IP", cell: (s) => s.nas_ip || "—" },
          { id: "framed", header: "Framed IP", cell: (s) => s.framed_ip || "—" },
          { id: "duration", header: "Duration", cell: (s) => fmtDuration(s.session_time ?? 0) },
          { id: "in", header: "Data in", cell: (s) => fmtBytes(s.input_octets) },
          { id: "out", header: "Data out", cell: (s) => fmtBytes(s.output_octets) },
          { id: "id", header: "Session ID", cell: (s) => s.session_id || "—" },
        ]}
        items={rows}
        empty={
          err ? (
            <StatusIndicator type="error">{err}</StatusIndicator>
          ) : (
            <Box textAlign="center" color="inherit">
              No active sessions
            </Box>
          )
        }
      />
    </ContentLayout>
  );
}
