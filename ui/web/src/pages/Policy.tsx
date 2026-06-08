import { useEffect, useState } from "react";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Input from "@cloudscape-design/components/input";
import Select from "@cloudscape-design/components/select";
import Toggle from "@cloudscape-design/components/toggle";
import FormField from "@cloudscape-design/components/form-field";
import AttributeEditor from "@cloudscape-design/components/attribute-editor";
import ExpandableSection from "@cloudscape-design/components/expandable-section";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Alert from "@cloudscape-design/components/alert";
import { get, put, post } from "../api";

// ---- model (mirrors the server's policy.rs) ----
type Effect = "accept" | "reject";
interface Attr { name: string; value: string }
interface AttrCond { type: "attr"; attribute: string; operator: string; value: string }
type Condition =
  | { type: "always" }
  | AttrCond
  | { type: "all"; conditions: Condition[] }
  | { type: "any"; conditions: Condition[] }
  | { type: "not"; condition: Condition };
interface Profile { id: string; name: string; effect: Effect; attributes: Attr[]; reply_message?: string }
interface Rule { id: string; name: string; enabled: boolean; condition: Condition; profile: string }
interface PolicySet { id: string; name: string; enabled: boolean; condition: Condition; rules: Rule[] }
interface Policy { policy_sets: PolicySet[]; authz_profiles: Profile[]; default_profile?: string }
interface Decision { effect: Effect; policy_set?: string; rule?: string; profile?: string; attributes?: Attr[]; reason: string }

const uid = (p: string) => `${p}-${Math.random().toString(36).slice(2, 8)}`;
const OPERATORS = ["equals", "not_equals", "contains", "starts_with", "ends_with", "matches_regex", "in_cidr"];

// ---- recursive condition editor (Phase 3b: nested ALL/ANY groups + NOT) ----
const newAttr = (): AttrCond => ({ type: "attr", attribute: "", operator: "equals", value: "" });
const newGroup = (): Condition => ({ type: "all", conditions: [newAttr()] });

// A group as the editor sees it: an ALL/ANY operator, an optional NOT wrapper,
// and child conditions (each of which may itself be a leaf or a nested group).
interface GroupView { negated: boolean; op: "all" | "any"; children: Condition[] }
function asGroup(c: Condition): GroupView | null {
  if (c.type === "not") {
    const inner = c.condition;
    if (inner.type === "all" || inner.type === "any")
      return { negated: true, op: inner.type, children: inner.conditions };
    return { negated: true, op: "all", children: [inner] }; // not(attr) → negated group of one
  }
  if (c.type === "all" || c.type === "any") return { negated: false, op: c.type, children: c.conditions };
  return null;
}
function fromGroup(g: GroupView): Condition {
  const grp: Condition = { type: g.op, conditions: g.children };
  return g.negated ? { type: "not", condition: grp } : grp;
}

// A single leaf condition row: attribute / operator / value.
function AttrRow({
  value,
  onChange,
  onRemove,
  attrOptions,
}: {
  value: AttrCond;
  onChange: (c: AttrCond) => void;
  onRemove: () => void;
  attrOptions: { label: string; value: string }[];
}) {
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
      <div style={{ flex: 2, minWidth: 150 }}>
        <Select
          selectedOption={value.attribute ? { value: value.attribute, label: value.attribute } : null}
          options={attrOptions}
          filteringType="auto"
          placeholder="attribute"
          onChange={(e) => onChange({ ...value, attribute: e.detail.selectedOption.value! })}
        />
      </div>
      <div style={{ flex: 1, minWidth: 130 }}>
        <Select
          selectedOption={{ value: value.operator || "equals", label: value.operator || "equals" }}
          options={OPERATORS.map((o) => ({ value: o, label: o }))}
          onChange={(e) => onChange({ ...value, operator: e.detail.selectedOption.value! })}
        />
      </div>
      <div style={{ flex: 2, minWidth: 130 }}>
        <Input value={value.value} placeholder="value" onChange={(e) => onChange({ ...value, value: e.detail.value })} />
      </div>
      <Button iconName="remove" variant="icon" ariaLabel="Remove condition" onClick={onRemove} />
    </div>
  );
}

// Recursive editor for an ALL/ANY (optionally NOT-wrapped) group. Children may be
// leaf rows or nested groups, mirroring the server's recursive Condition tree.
function GroupEditor({
  value,
  onChange,
  onRemove,
  attrOptions,
  depth,
}: {
  value: Condition;
  onChange: (c: Condition) => void;
  onRemove: () => void;
  attrOptions: { label: string; value: string }[];
  depth: number;
}) {
  const g = asGroup(value);
  if (!g) return <Alert type="info">Unsupported condition node; left unchanged.</Alert>;
  const set = (patch: Partial<GroupView>) => onChange(fromGroup({ ...g, ...patch }));
  const setChild = (i: number, c: Condition) => set({ children: g.children.map((x, j) => (j === i ? c : x)) });
  const removeChild = (i: number) => set({ children: g.children.filter((_, j) => j !== i) });
  return (
    <div style={{ borderLeft: "2px solid #b6bec9", paddingLeft: 12 }}>
      <SpaceBetween size="xs">
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <Toggle checked={g.negated} onChange={(e) => set({ negated: e.detail.checked })}>NOT</Toggle>
          <div style={{ width: 150 }}>
            <Select
              selectedOption={{ value: g.op, label: g.op === "all" ? "Match ALL of" : "Match ANY of" }}
              options={[
                { value: "all", label: "Match ALL of" },
                { value: "any", label: "Match ANY of" },
              ]}
              onChange={(e) => set({ op: e.detail.selectedOption.value as "all" | "any" })}
            />
          </div>
          <div style={{ flex: 1 }} />
          <Button iconName="add-plus" onClick={() => set({ children: [...g.children, newAttr()] })}>Condition</Button>
          <Button iconName="add-plus" onClick={() => set({ children: [...g.children, newGroup()] })}>Group</Button>
          <Button
            iconName={depth === 0 ? "close" : "remove"}
            variant="icon"
            ariaLabel={depth === 0 ? "Clear all conditions" : "Remove group"}
            onClick={onRemove}
          />
        </div>
        {g.children.length === 0 && (
          <Box color="text-status-inactive" fontSize="body-s">Empty group — add a condition (an empty group is rejected on save).</Box>
        )}
        {g.children.map((child, i) =>
          child.type === "attr" ? (
            <AttrRow key={i} value={child} attrOptions={attrOptions} onChange={(c) => setChild(i, c)} onRemove={() => removeChild(i)} />
          ) : (
            <GroupEditor key={i} value={child} depth={depth + 1} attrOptions={attrOptions} onChange={(c) => setChild(i, c)} onRemove={() => removeChild(i)} />
          )
        )}
      </SpaceBetween>
    </div>
  );
}

function ConditionEditor({
  value,
  onChange,
  attrOptions,
}: {
  value: Condition;
  onChange: (c: Condition) => void;
  attrOptions: { label: string; value: string }[];
}) {
  if (value.type === "always")
    return (
      <SpaceBetween size="xs">
        <Box color="text-status-inactive">Always matches (no conditions).</Box>
        <Button iconName="add-plus" onClick={() => onChange(newGroup())}>Add conditions</Button>
      </SpaceBetween>
    );
  // A bare leaf at the root is editable as a single-child group (all([attr]) ≡ attr).
  const editable: Condition = value.type === "attr" ? { type: "all", conditions: [value] } : value;
  return (
    <GroupEditor
      value={editable}
      depth={0}
      attrOptions={attrOptions}
      onChange={onChange}
      onRemove={() => onChange({ type: "always" })}
    />
  );
}

export default function PolicyPage() {
  const [policy, setPolicy] = useState<Policy>({ policy_sets: [], authz_profiles: [] });
  const [attrOptions, setAttrOptions] = useState<{ label: string; value: string }[]>([]);
  const [replyAttrOptions, setReplyAttrOptions] = useState<{ label: string; value: string }[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = () => {
    get<Policy>("/api/policy")
      .then((p) => {
        setErr(null);
        setPolicy({ policy_sets: p.policy_sets ?? [], authz_profiles: p.authz_profiles ?? [], default_profile: p.default_profile });
      })
      .catch((e) => setErr(String(e)));
    get<{ attributes: { name: string }[]; reply_attributes: string[] }>("/api/dictionary")
      .then((d) => {
        setAttrOptions(d.attributes.map((a) => ({ label: a.name, value: a.name })));
        setReplyAttrOptions((d.reply_attributes ?? []).map((n) => ({ label: n, value: n })));
      })
      .catch(() => {});
  };
  useEffect(load, []);

  const profileOptions = policy.authz_profiles.map((p) => ({ label: p.name, value: p.id }));

  const save = () => {
    setSaving(true);
    setErr(null);
    setSaved(null);
    put<Policy>("/api/policy", policy)
      .then(() => setSaved("Policy saved."))
      .catch((e) => setErr(String(e).replace(/^Error:\s*/, "")))
      .finally(() => setSaving(false));
  };

  // ---- profile editing ----
  const updateProfile = (id: string, patch: Partial<Profile>) =>
    setPolicy({ ...policy, authz_profiles: policy.authz_profiles.map((p) => (p.id === id ? { ...p, ...patch } : p)) });
  const addProfile = () =>
    setPolicy({ ...policy, authz_profiles: [...policy.authz_profiles, { id: uid("p"), name: "New profile", effect: "accept", attributes: [] }] });
  const removeProfile = (id: string) =>
    setPolicy({
      ...policy,
      authz_profiles: policy.authz_profiles.filter((p) => p.id !== id),
      // Drop a dangling default reference so Save doesn't fail with an
      // invisible "default_profile not defined" error.
      default_profile: policy.default_profile === id ? undefined : policy.default_profile,
    });

  // ---- set / rule editing ----
  const updateSet = (id: string, patch: Partial<PolicySet>) =>
    setPolicy({ ...policy, policy_sets: policy.policy_sets.map((s) => (s.id === id ? { ...s, ...patch } : s)) });
  const addSet = () =>
    setPolicy({ ...policy, policy_sets: [...policy.policy_sets, { id: uid("s"), name: "New policy set", enabled: true, condition: { type: "always" }, rules: [] }] });
  const removeSet = (id: string) => setPolicy({ ...policy, policy_sets: policy.policy_sets.filter((s) => s.id !== id) });
  const moveSet = (idx: number, dir: -1 | 1) => {
    const arr = [...policy.policy_sets];
    const j = idx + dir;
    if (j < 0 || j >= arr.length) return;
    [arr[idx], arr[j]] = [arr[j], arr[idx]];
    setPolicy({ ...policy, policy_sets: arr });
  };
  const setRules = (setId: string, rules: Rule[]) => updateSet(setId, { rules });

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="ISE-style authorization policy builder. Edit profiles, policy sets and rules, then Save. Saved policy is enforced live on the Access-Accept path. Conditions support nested ALL/ANY groups and NOT."
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button iconName="refresh" onClick={load}>Reload</Button>
              <Button variant="primary" onClick={save} loading={saving}>Save policy</Button>
            </SpaceBetween>
          }
        >
          Policy
        </Header>
      }
    >
      <SpaceBetween size="l">
        {err && <Alert type="error" header="Save failed">{err}</Alert>}
        {saved && <Alert type="success" dismissible onDismiss={() => setSaved(null)}>{saved}</Alert>}

        {/* Authorization profiles */}
        <Container header={<Header variant="h2" counter={`(${policy.authz_profiles.length})`} actions={<Button onClick={addProfile} iconName="add-plus">Add profile</Button>}>Authorization profiles</Header>}>
          <SpaceBetween size="s">
            {policy.authz_profiles.length === 0 && <Box color="text-status-inactive">No profiles yet.</Box>}
            {policy.authz_profiles.map((p) => (
              <ExpandableSection key={p.id} headerText={`${p.name} (${p.effect})`} variant="container">
                <SpaceBetween size="s">
                  <ColumnLayout columns={2}>
                    <FormField label="Name"><Input value={p.name} onChange={(e) => updateProfile(p.id, { name: e.detail.value })} /></FormField>
                    <FormField label="Effect">
                      <Select selectedOption={{ value: p.effect, label: p.effect }} options={[{ value: "accept", label: "accept" }, { value: "reject", label: "reject" }]} onChange={(e) => updateProfile(p.id, { effect: e.detail.selectedOption.value as Effect })} />
                    </FormField>
                  </ColumnLayout>
                  <FormField label="Returned RADIUS attributes (on accept)">
                    <AttributeEditor<Attr>
                      items={p.attributes}
                      addButtonText="Add attribute"
                      removeButtonText="Remove"
                      empty="None"
                      definition={[
                        { label: "Attribute", control: (it, i) => <Select selectedOption={it.name ? { label: it.name, value: it.name } : null} options={replyAttrOptions} placeholder="select an attribute" onChange={(e) => updateProfile(p.id, { attributes: p.attributes.map((a, j) => (j === i ? { ...a, name: e.detail.selectedOption.value! } : a)) })} /> },
                        { label: "Value", control: (it, i) => <Input value={it.value} onChange={(e) => updateProfile(p.id, { attributes: p.attributes.map((a, j) => (j === i ? { ...a, value: e.detail.value } : a)) })} /> },
                      ]}
                      onAddButtonClick={() => updateProfile(p.id, { attributes: [...p.attributes, { name: "", value: "" }] })}
                      onRemoveButtonClick={({ detail }) => updateProfile(p.id, { attributes: p.attributes.filter((_, i) => i !== detail.itemIndex) })}
                    />
                  </FormField>
                  <Box><Button onClick={() => removeProfile(p.id)} iconName="remove">Delete profile</Button></Box>
                </SpaceBetween>
              </ExpandableSection>
            ))}
          </SpaceBetween>
        </Container>

        {/* Policy sets */}
        <Container header={<Header variant="h2" counter={`(${policy.policy_sets.length})`} actions={<Button onClick={addSet} iconName="add-plus">Add policy set</Button>}>Policy sets (evaluated in order)</Header>}>
          <SpaceBetween size="s">
            <FormField label="Default result" description="Applied when the selected set matches no rule, or no set matches. Defaults to reject.">
              <Select
                selectedOption={
                  policy.default_profile
                    ? profileOptions.find((o) => o.value === policy.default_profile) ?? { value: policy.default_profile, label: `${policy.default_profile} (missing)` }
                    : { value: "", label: "Reject (implicit)" }
                }
                options={[{ value: "", label: "Reject (implicit)" }, ...profileOptions]}
                onChange={(e) => {
                  const v = e.detail.selectedOption.value;
                  setPolicy({ ...policy, default_profile: v || undefined });
                }}
              />
            </FormField>
            {policy.policy_sets.length === 0 && <Box color="text-status-inactive">No policy sets yet.</Box>}
            {policy.policy_sets.map((s, idx) => (
              <ExpandableSection key={s.id} defaultExpanded headerText={`${idx + 1}. ${s.name}`} variant="container">
                <SpaceBetween size="m">
                  <ColumnLayout columns={2}>
                    <FormField label="Set name"><Input value={s.name} onChange={(e) => updateSet(s.id, { name: e.detail.value })} /></FormField>
                    <Box float="right">
                      <SpaceBetween direction="horizontal" size="xs">
                        <Button iconName="angle-up" disabled={idx === 0} onClick={() => moveSet(idx, -1)} />
                        <Button iconName="angle-down" disabled={idx === policy.policy_sets.length - 1} onClick={() => moveSet(idx, 1)} />
                        <Button iconName="remove" onClick={() => removeSet(s.id)}>Delete set</Button>
                      </SpaceBetween>
                    </Box>
                  </ColumnLayout>

                  <FormField label="This set applies when" description="Gate for the whole set.">
                    <ConditionEditor value={s.condition} attrOptions={attrOptions} onChange={(c) => updateSet(s.id, { condition: c })} />
                  </FormField>

                  <Box variant="h4">Rules</Box>
                  <RuleList setId={s.id} rules={s.rules} profileOptions={profileOptions} attrOptions={attrOptions} onChange={(r) => setRules(s.id, r)} />
                </SpaceBetween>
              </ExpandableSection>
            ))}
          </SpaceBetween>
        </Container>

        <SimulatePanel policy={policy} />
      </SpaceBetween>
    </ContentLayout>
  );
}

function RuleList({
  setId,
  rules,
  profileOptions,
  attrOptions,
  onChange,
}: {
  setId: string;
  rules: Rule[];
  profileOptions: { label: string; value: string }[];
  attrOptions: { label: string; value: string }[];
  onChange: (r: Rule[]) => void;
}) {
  const update = (id: string, patch: Partial<Rule>) => onChange(rules.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  const add = () => onChange([...rules, { id: uid("r"), name: "New rule", enabled: true, condition: { type: "always" }, profile: profileOptions[0]?.value ?? "" }]);
  return (
    <SpaceBetween size="xs">
      {rules.length === 0 && <Box color="text-status-inactive">No rules — the set will fall through to the default.</Box>}
      {rules.map((r) => (
        <ExpandableSection key={r.id} headerText={r.name} variant="footer">
          <SpaceBetween size="s">
            <ColumnLayout columns={2}>
              <FormField label="Rule name"><Input value={r.name} onChange={(e) => update(r.id, { name: e.detail.value })} /></FormField>
              <FormField label="Result (authorization profile)">
                <Select selectedOption={profileOptions.find((o) => o.value === r.profile) ?? null} options={profileOptions} placeholder="select a profile" onChange={(e) => update(r.id, { profile: e.detail.selectedOption.value! })} />
              </FormField>
            </ColumnLayout>
            <FormField label="Conditions">
              <ConditionEditor value={r.condition} attrOptions={attrOptions} onChange={(c) => update(r.id, { condition: c })} />
            </FormField>
            <Box><Button iconName="remove" onClick={() => onChange(rules.filter((x) => x.id !== r.id))}>Delete rule</Button></Box>
          </SpaceBetween>
        </ExpandableSection>
      ))}
      <Box><Button iconName="add-plus" onClick={add}>Add rule</Button></Box>
    </SpaceBetween>
  );
}

function SimulatePanel({ policy }: { policy: Policy }) {
  const [attrs, setAttrs] = useState<Attr[]>([
    { name: "NAS-Port-Type", value: "Wireless-802.11" },
    { name: "identity-group", value: "staff" },
  ]);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [simErr, setSimErr] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const run = () => {
    setRunning(true);
    setSimErr(null);
    const request = { attributes: Object.fromEntries(attrs.filter((a) => a.name).map((a) => [a.name, a.value])) };
    post<Decision>("/api/policy/dry-run", { policy, request })
      .then((d) => {
        setDecision(d);
      })
      .catch((e) => {
        setDecision(null);
        setSimErr(String(e).replace(/^Error:\s*/, ""));
      })
      .finally(() => setRunning(false));
  };
  return (
    <Container header={<Header variant="h2" description="Evaluate the current (unsaved) policy against a sample request.">Simulate</Header>}>
      <SpaceBetween size="m">
        {simErr && <Alert type="error" header="Simulation failed">{simErr}</Alert>}
        <AttributeEditor<Attr>
          items={attrs}
          addButtonText="Add attribute"
          removeButtonText="Remove"
          empty="No request attributes"
          definition={[
            { label: "Attribute", control: (it, i) => <Input value={it.name} placeholder="e.g. User-Name" onChange={(e) => setAttrs(attrs.map((a, j) => (j === i ? { ...a, name: e.detail.value } : a)))} /> },
            { label: "Value", control: (it, i) => <Input value={it.value} onChange={(e) => setAttrs(attrs.map((a, j) => (j === i ? { ...a, value: e.detail.value } : a)))} /> },
          ]}
          onAddButtonClick={() => setAttrs([...attrs, { name: "", value: "" }])}
          onRemoveButtonClick={({ detail }) => setAttrs(attrs.filter((_, i) => i !== detail.itemIndex))}
        />
        <Button variant="primary" onClick={run} loading={running}>Run simulation</Button>
        {decision && (
          <ColumnLayout columns={2} variant="text-grid">
            <div><Box variant="awsui-key-label">Effect</Box><StatusIndicator type={decision.effect === "accept" ? "success" : "error"}>{decision.effect}</StatusIndicator></div>
            <div><Box variant="awsui-key-label">Matched</Box>{decision.policy_set ? `${decision.policy_set} → ${decision.rule}` : "—"}</div>
            <div><Box variant="awsui-key-label">Returned attributes</Box>{decision.attributes?.length ? decision.attributes.map((a) => `${a.name}=${a.value}`).join(", ") : "—"}</div>
            <div><Box variant="awsui-key-label">Reason</Box>{decision.reason}</div>
          </ColumnLayout>
        )}
      </SpaceBetween>
    </Container>
  );
}
