module.exports = function (c) {
  return { markdownTemplateEngine: "njk", htmlTemplateEngine: "njk", dir: { includes: "_includes", data: "_data" } };
};
