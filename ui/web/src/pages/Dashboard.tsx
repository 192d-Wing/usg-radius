import { useEffect, useState, ReactNode } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Box from "@cloudscape-design/components/box";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Table from "@cloudscape-design/components/table";
import Button from "@cloudscape-design/components/button";
import { get, Overview, fmtDuration } from "../api";

export default function DashboardPage() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    get<Overview>("/api/overview")
      .then((d) => {
        setOv(d);
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
          description="Live status of the RADIUS service (read-only)."
          actions={<Button iconName="refresh" onClick={load} loading={loading} />}
        >
          Dashboard
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Service health</Header>}>
          {err ? (
            <StatusIndicator type="error">Cannot reach the RADIUS metrics endpoint: {err}</StatusIndicator>
          ) : (
            <ColumnLayout columns={4} variant="text-grid">
              <Stat label="State backend">
                <StatusIndicator type={ov?.backend_up ? "success" : "error"}>
                  {ov?.backend ?? "—"} {ov?.backend_up ? "up" : "down"}
                </StatusIndicator>
              </Stat>
              <Stat label="Uptime">{fmtDuration(ov?.uptime_seconds ?? NaN)}</Stat>
              <Stat label="Dedup cache entries">{ov?.cache_entries ?? "—"}</Stat>
              <Stat label="Exposed metrics">{ov?.metrics?.length ?? 0}</Stat>
            </ColumnLayout>
          )}
        </Container>

        <Table
          header={<Header variant="h2" counter={`(${ov?.metrics?.length ?? 0})`}>Metrics</Header>}
          variant="container"
          loading={loading && !ov}
          loadingText="Loading metrics…"
          columnDefinitions={[
            { id: "name", header: "Metric", cell: (m) => m.name },
            {
              id: "labels",
              header: "Labels",
              cell: (m) =>
                m.labels && Object.keys(m.labels).length
                  ? Object.entries(m.labels)
                      .map(([k, v]) => `${k}="${v}"`)
                      .join(", ")
                  : "—",
            },
            { id: "value", header: "Value", cell: (m) => String(m.value) },
          ]}
          items={ov?.metrics ?? []}
          empty={<Box textAlign="center">No metrics</Box>}
        />
      </SpaceBetween>
    </ContentLayout>
  );
}

function Stat({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <div>{children}</div>
    </div>
  );
}
