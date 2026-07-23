import syntaxHighlight from "@11ty/eleventy-plugin-syntaxhighlight";
import { EleventyHtmlBasePlugin } from "@11ty/eleventy";

export default function (eleventyConfig) {
  // Syntax highlighting (build-time Prism, no client JS / CDN needed)
  eleventyConfig.addPlugin(syntaxHighlight);

  // Rewrite all root-relative URLs (assets, links, markdown images) to include
  // the pathPrefix — required for GitHub Pages project-site subpath hosting.
  eleventyConfig.addPlugin(EleventyHtmlBasePlugin);

  // Static assets, downloadable challenge files, and extracted images
  eleventyConfig.addPassthroughCopy({ "src/assets": "assets" });
  eleventyConfig.addPassthroughCopy("src/files");
  eleventyConfig.addPassthroughCopy("src/img");

  // Collection of all write-ups, ordered by category then points (desc)
  eleventyConfig.addCollection("writeups", (collectionApi) => {
    const partOrder = { Quals: 1, Final: 2 };
    const order = { Crypto: 1, Pwn: 2, Rev: 3, Web: 4, Foren: 5, Misc: 6 };
    return collectionApi
      .getFilteredByGlob("src/writeups/**/*.md")
      .sort((a, b) => {
        const pa = partOrder[a.data.part] ?? 99;
        const pb = partOrder[b.data.part] ?? 99;
        if (pa !== pb) return pa - pb;
        const ca = order[a.data.category] ?? 99;
        const cb = order[b.data.category] ?? 99;
        if (ca !== cb) return ca - cb;
        return (b.data.points ?? 0) - (a.data.points ?? 0);
      });
  });

  return {
    dir: {
      input: "src",
      output: "_site",
      includes: "_includes",
      data: "_data",
    },
    markdownTemplateEngine: false,
    htmlTemplateEngine: "njk",
    templateFormats: ["njk", "md", "11ty.js"],
    pathPrefix: "/gemastik-18-ctf-2025/",
  };
}
