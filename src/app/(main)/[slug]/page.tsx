import { getArticleBySlug } from "@/services/article";

export default async function ArticleDetail({
  params,
}: {
  params: { slug: string };
}) {
  const { slug } = await params;
  const article = await getArticleBySlug(slug);

  console.log(article);
  return (
    <div>
      <img src={article.image_path} />
      <div>{article.title}</div>
    </div>
  );
}