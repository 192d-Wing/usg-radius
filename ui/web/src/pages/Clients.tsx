import { useEffect, useState } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import { get, Client } from "../api";

export default function ClientsPage() {
  const [rows, setRows] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    get<Client[]>("/api/clients")
      .then((d) => {
        setRows(d);
        setErr(null);
      })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  };
  useEffect(load, []);

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Network Access Servers authorized to talk to this RADIUS server (read-only; shared secrets are not shown)."
          actions={<Button iconName="refresh" onClick={load} loading={loading} />}
        >
          Clients (NAS)
        </Header>
      }
    >
      <Table
        variant="container"
        header={<Header counter={`(${rows.length})`}>Authorized clients</Header>}
        loading={loading && rows.length === 0}
        loadingText="Loading clients…"
        columnDefinitions={[
          { id: "address", header: "Address / CIDR", cell: (c) => c.address },
          { id: "name", header: "Name", cell: (c) => c.name || "—" },
          { id: "nas", header: "NAS-Identifier", cell: (c) => c.nas_identifier || "—" },
          {
            id: "enabled",
            header: "Status",
            cell: (c) => (
              <StatusIndicator type={c.enabled ? "success" : "stopped"}>
                {c.enabled ? "enabled" : "disabled"}
              </StatusIndicator>
            ),
          },
        ]}
        items={rows}
        empty={
          err ? (
            <StatusIndicator type="error">{err}</StatusIndicator>
          ) : (
            <Box textAlign="center" color="inherit">
              No clients configured
            </Box>
          )
        }
      />
    </ContentLayout>
  );
}
