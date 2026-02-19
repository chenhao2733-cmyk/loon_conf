/**
 * QQ Video getvinfo
 * response-body-replace-regex:
 * &sppreviewtype=\d(.*)&spsrt=\d
 * =>
 * &sppreviewtype=0$1&spsrt=0
 */

(function () {
  try {
    let body = $response.body;
    if (!body) return $done({});

    body = body.replace(
      /&sppreviewtype=\d(.*)&spsrt=\d/g,
      "&sppreviewtype=0$1&spsrt=0"
    );

    $done({ body });
  } catch (e) {
    $done({ body: $response.body });
  }
})();
