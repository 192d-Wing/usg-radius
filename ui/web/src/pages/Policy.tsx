import { useEffect, useState } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Table from "@cloudscape-design/components/table";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Input from "@cloudscape-design/components/input";
import AttributeEditor from "@cloudscape-design/components/attribute-editor";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import { get, post } from "../api";

interface Profile {
  id: string;
  name: string;
  effect: "accept" | "reject";
  attributes?: { name: string; value: string }[];
}
interface PolicySet {
  id: string;
  name: string;
  enabled?: boolean;
  rules: { id: string; name: string }[];
}
interface Policy {
  policy_sets: PolicySet[];
  authz_profiles: Profile[];
  default_profile?: string;
}
interface Decision {
  effect: "accept" | "reject";
  policy_set?: string;
  rule?: string;
  profile?: string;
  attributes?: { name: string; value: string }[];
  reply_message?: string;
  reason: string;
}
type Attr = { name: string; value: string };

export default function PolicyPage() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [attrs, setAttrs] = useState<Attr[]>([
    { name: "NAS-Port-Type", value: "Wireless-802.11" },
    { name: "identity-group", value: "staff" },
  ]);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [running, setRunning] = useState(false);

  const load = () => {
    get<Policy>("/api/policy")
      .then((p) => {
        setPolicy(p);
        setErr(null);
      })
      .catch((e) => setErr(String(e)));
  };
  useEffect(load, []);

  const simulate = () => {
    if (!policy) return;
    setRunning(true);
    const request = {
      attributes: Object.fromEntries(attrs.filter((a) => a.name).map((a) => [a.name, a.value])),
    };
    post<Decision>("/api/policy/dry-run", { policy, request })
      .then(setDecision)
      .catch((e) => setErr(String(e)))
      .finally(() => setRunning(false));
  };

  const sets = policy?.policy_sets ?? [];
  const profiles = policy?.authz_profiles ?? [];

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="ISE-style authorization policy (read-only view + Simulate). The visual builder lands in Phase 3; the engine is not yet enforced in the live request path."
          actions={<Button iconName="refresh" onClick={load} />}
        >
          Policy
        </Header>
      }
    >
      <SpaceBetween size="l">
        {err && <StatusIndicator type="error">{err}</StatusIndicator>}

        <Table
          variant="container"
          header={<Header counter={`(${sets.length})`}>Policy sets</Header>}
          columnDefinitions={[
            { id: "name", header: "Name", cell: (s) => s.name },
            { id: "enabled", header: "Enabled", cell: (s) => (s.enabled === false ? "no" : "yes") },
            { id: "rules", header: "Rules", cell: (s) => s.rules?.length ?? 0 },
          ]}
          items={sets}
          empty={
            <Box textAlign="center" color="inherit">
              No policy loaded. Set <b>POLICY_FILE</b> on the server, or build one in Phase 3.
            </Box>
          }
        />

        <Table
          variant="container"
          header={<Header counter={`(${profiles.length})`}>Authorization profiles</Header>}
          columnDefinitions={[
            { id: "name", header: "Name", cell: (p) => p.name },
            {
              id: "effect",
              header: "Effect",
              cell: (p) => (
                <StatusIndicator type={p.effect === "accept" ? "success" : "stopped"}>
                  {p.effect}
                </StatusIndicator>
              ),
            },
            { id: "attrs", header: "Returned attributes", cell: (p) => p.attributes?.length ?? 0 },
          ]}
          items={profiles}
          empty={
            <Box textAlign="center" color="inherit">
              No authorization profiles
            </Box>
          }
        />

        <Container header={<Header variant="h2" description="Evaluate the loaded policy against a sample request.">Simulate</Header>}>
          <SpaceBetween size="m">
            <AttributeEditor<Attr>
              items={attrs}
              addButtonText="Add attribute"
              removeButtonText="Remove"
              empty="No request attributes"
              definition={[
                {
                  label: "Attribute",
                  control: (item, i) => (
                    <Input
                      value={item.name}
                      placeholder="e.g. User-Name"
                      onChange={(e) =>
                        setAttrs(attrs.map((a, j) => (j === i ? { ...a, name: e.detail.value } : a)))
                      }
                    />
                  ),
                },
                {
                  label: "Value",
                  control: (item, i) => (
                    <Input
                      value={item.value}
                      onChange={(e) =>
                        setAttrs(attrs.map((a, j) => (j === i ? { ...a, value: e.detail.value } : a)))
                      }
                    />
                  ),
                },
              ]}
              onAddButtonClick={() => setAttrs([...attrs, { name: "", value: "" }])}
              onRemoveButtonClick={({ detail }) =>
                setAttrs(attrs.filter((_, i) => i !== detail.itemIndex))
              }
            />
            <Button variant="primary" onClick={simulate} loading={running} disabled={!policy}>
              Run simulation
            </Button>

            {decision && (
              <Container header={<Header variant="h3">Decision</Header>}>
                <ColumnLayout columns={2} variant="text-grid">
                  <div>
                    <Box variant="awsui-key-label">Effect</Box>
                    <StatusIndicator type={decision.effect === "accept" ? "success" : "error"}>
                      {decision.effect}
                    </StatusIndicator>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Matched</Box>
                    {decision.policy_set ? `${decision.policy_set} → ${decision.rule}` : "—"}
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Profile</Box>
                    {decision.profile ?? "—"}
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Returned attributes</Box>
                    {decision.attributes?.length
                      ? decision.attributes.map((a) => `${a.name}=${a.value}`).join(", ")
                      : "—"}
                  </div>
                  <div style={{ gridColumn: "1 / -1" }}>
                    <Box variant="awsui-key-label">Reason</Box>
                    {decision.reason}
                  </div>
                </ColumnLayout>
              </Container>
            )}
          </SpaceBetween>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
