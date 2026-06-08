import Placeholder from "./Placeholder";

export default function ClientsPage() {
  return (
    <Placeholder
      title="Clients (NAS)"
      phase="Phase 1 — needs the server management API (/api/v1/clients)"
      description="Network Access Servers authorized to talk to this RADIUS server."
      bullets={[
        "CRUD for clients (IP/CIDR, shared secret, name, NAS-Identifier)",
        "Group NAS devices into device groups (by CIDR) for policy conditions",
        "Enable/disable without deleting",
      ]}
    />
  );
}
