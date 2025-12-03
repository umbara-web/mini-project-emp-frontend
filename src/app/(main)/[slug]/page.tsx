import { getEventBySlug } from "@/src/services/event";

export default async function ArticleDetail({
  params,
}: {
  params: { slug: string };
}) {
  const { slug } = await params;
  const event = await getEventBySlug(slug);

  console.log(event);
  return (
    <div>
      <div>
        <h1>event</h1>
      </div>
    </div>
  );
}