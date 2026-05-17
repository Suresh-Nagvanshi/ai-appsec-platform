export default async function FindingDetailsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <div>
      <h1 className="text-3xl font-bold">Finding {id}</h1>
      <p className="text-muted-foreground mt-1">Detailed analysis and remediation steps.</p>
    </div>
  );
}
