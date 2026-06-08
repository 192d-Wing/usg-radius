import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import Container from "@cloudscape-design/components/container";
import Box from "@cloudscape-design/components/box";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import SpaceBetween from "@cloudscape-design/components/space-between";

// Shared "coming in a later phase" page used by the not-yet-built sections.
export default function Placeholder({
  title,
  phase,
  description,
  bullets,
}: {
  title: string;
  phase: string;
  description: string;
  bullets: string[];
}) {
  return (
    <ContentLayout header={<Header variant="h1" description={description}>{title}</Header>}>
      <Container header={<Header variant="h2">Planned</Header>}>
        <SpaceBetween size="m">
          <StatusIndicator type="pending">{phase}</StatusIndicator>
          <Box>
            <ul>
              {bullets.map((b) => (
                <li key={b}>{b}</li>
              ))}
            </ul>
          </Box>
        </SpaceBetween>
      </Container>
    </ContentLayout>
  );
}
