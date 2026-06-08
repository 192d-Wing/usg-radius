import Placeholder from "./Placeholder";

export default function SessionsPage() {
  return (
    <Placeholder
      title="Sessions"
      phase="Phase 1 — needs the server management API (/api/v1/sessions)"
      description="Live RADIUS authentication & accounting sessions."
      bullets={[
        "Live table of active sessions (user, NAS, framed IP, start, in/out octets)",
        "Filter by NAS / user; auto-refresh",
        "Drill-in to a session's accounting timeline",
      ]}
    />
  );
}
