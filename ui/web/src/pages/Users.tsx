import { useEffect, useState } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import { get, User } from "../api";

export default function UsersPage() {
  const [rows, setRows] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    get<User[]>("/api/users")
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
          description="Local users (read-only; passwords are not shown). Prefer LDAP/AD or PostgreSQL for production identities."
          actions={<Button iconName="refresh" onClick={load} loading={loading} />}
        >
          Users
        </Header>
      }
    >
      <Table
        variant="container"
        header={<Header counter={`(${rows.length})`}>Local users</Header>}
        loading={loading && rows.length === 0}
        loadingText="Loading users…"
        columnDefinitions={[
          { id: "username", header: "Username", cell: (u) => u.username },
          {
            id: "attributes",
            header: "Attributes",
            cell: (u) => {
              const e = Object.entries(u.attributes || {});
              return e.length ? e.map(([k, v]) => `${k}=${v}`).join(", ") : "—";
            },
          },
        ]}
        items={rows}
        empty={
          err ? (
            <StatusIndicator type="error">{err}</StatusIndicator>
          ) : (
            <Box textAlign="center" color="inherit">
              No local users
            </Box>
          )
        }
      />
    </ContentLayout>
  );
}
