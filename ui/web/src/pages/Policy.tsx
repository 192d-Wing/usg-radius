import Placeholder from "./Placeholder";

export default function PolicyPage() {
  return (
    <Placeholder
      title="Policy"
      phase="Phases 2–3 — needs the policy engine + management API"
      description="ISE-style authorization policy: policy sets, rules, and authorization profiles."
      bullets={[
        "Policy Sets table (ordered, drag-to-reorder, enable/disable)",
        "Condition Studio: nested AND/OR of attribute · operator · value",
        "Authorization Profiles: returned RADIUS attributes (VLAN, Filter-Id, dACL…)",
        "Simulate / dry-run a candidate policy against recent requests",
      ]}
    />
  );
}
