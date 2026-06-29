import { siteConfig } from "../../config";

export type SeoJsonLdOptions = {
  title: string;
  description: string;
  canonicalUrl: string;
  pageType: "website" | "article";
  publishedTime?: Date;
  author?: string;
};

export function seoKeywords(extraKeywords: string[] = []): string {
  return unique([...siteConfig.keywords, ...extraKeywords]).join(", ");
}

export function seoJsonLd(options: SeoJsonLdOptions): string {
  const authorName = options.author ?? siteConfig.author.name;
  const personId = `${siteConfig.url}#person`;
  const websiteId = `${siteConfig.url}#website`;
  const graph: Record<string, unknown>[] = [
    {
      "@type": "Person",
      "@id": personId,
      name: siteConfig.author.name,
      alternateName: siteConfig.author.handle,
      url: siteConfig.url,
      email: siteConfig.author.email,
      jobTitle: siteConfig.author.role,
      sameAs: siteConfig.author.sameAs
    },
    {
      "@type": "WebSite",
      "@id": websiteId,
      name: siteConfig.name,
      url: siteConfig.url,
      description: siteConfig.description,
      inLanguage: siteConfig.locale,
      publisher: { "@id": personId }
    }
  ];

  graph.push(
    options.pageType === "article"
      ? {
          "@type": "Article",
          headline: options.title,
          description: options.description,
          url: options.canonicalUrl,
          mainEntityOfPage: options.canonicalUrl,
          datePublished: options.publishedTime?.toISOString(),
          dateModified: options.publishedTime?.toISOString(),
          author: { "@type": "Person", name: authorName },
          publisher: { "@id": personId },
          isPartOf: { "@id": websiteId },
          inLanguage: siteConfig.locale
        }
      : {
          "@type": "WebPage",
          name: options.title,
          description: options.description,
          url: options.canonicalUrl,
          isPartOf: { "@id": websiteId },
          about: { "@id": personId },
          inLanguage: siteConfig.locale
        }
  );

  return JSON.stringify({ "@context": "https://schema.org", "@graph": graph });
}

function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
