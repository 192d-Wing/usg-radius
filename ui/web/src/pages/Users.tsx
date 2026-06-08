import Placeholder from "./Placeholder";

export default function UsersPage() {
  return (
    <Placeholder
      title="Users"
      phase="Phase 1 — needs the server management API (/api/v1/users)"
      description="Local users and identity-source configuration."
      bullets={[
        "CRUD for local users + attributes",
        "View configured identity sources (LDAP/AD, PostgreSQL)",
        "Map identity groups for use in policy conditions",
      ]}
    />
  );
}
