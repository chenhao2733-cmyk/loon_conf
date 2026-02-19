/**
 * 浙里办 selectStartPic
 * response-body-json-replace: data {}
 */
(function () {
  try {
    const body = $response.body || "";
    if (!body) return $done({});

    const obj = JSON.parse(body);
    if (typeof obj !== "object" || obj === null) return $done({ body });

    obj.data = {}; // 核心：把 data 替换成 {}

    return $done({ body: JSON.stringify(obj) });
  } catch (e) {
    // 出错则原样返回，避免影响正常使用
    return $done({ body: $response.body });
  }
})();
