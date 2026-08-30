function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}


function error(message, status = 400) {
  return json(
    {
      success: false,
      error: message
    },
    status
  );
}


async function getRestaurants(env) {

  const result = await env.DB
    .prepare(`
      SELECT
        id,
        name,
        category,
        filter,
        description,
        rating,
        address,
        phone,
        hours,
        image,
        emoji,
        featured
      FROM restaurants
      WHERE active = 1
      ORDER BY featured DESC, id ASC
    `)
    .all();


  return json({
    success: true,
    restaurants: result.results
  });

}


async function getPlaces(env) {

  const result = await env.DB
    .prepare(`
      SELECT
        id,
        name,
        category,
        description,
        address,
        image,
        emoji
      FROM places
      WHERE active = 1
      ORDER BY id ASC
    `)
    .all();


  return json({
    success: true,
    places: result.results
  });

}


async function createBusinessRequest(request, env) {

  let body;

  try {
    body = await request.json();
  } catch {
    return error("Geçersiz JSON.");
  }


  const businessName =
    String(body.business_name || "").trim();

  const category =
    String(body.category || "").trim();

  const phone =
    String(body.phone || "").trim();

  const address =
    String(body.address || "").trim();

  const message =
    String(body.message || "").trim();


  if (!businessName) {
    return error("İşletme adı zorunludur.");
  }


  if (!category) {
    return error("Kategori zorunludur.");
  }


  const result = await env.DB
    .prepare(`
      INSERT INTO business_requests
      (
        business_name,
        category,
        phone,
        address,
        message,
        status
      )
      VALUES (?, ?, ?, ?, ?, 'pending')
    `)
    .bind(
      businessName,
      category,
      phone,
      address,
      message
    )
    .run();


  return json(
    {
      success: true,
      id: result.meta.last_row_id,
      message: "Başvurunuz kaydedildi."
    },
    201
  );

}


export default {

  async fetch(request, env) {

    const url =
      new URL(request.url);

    const pathname =
      url.pathname;


    try {

      if (
        request.method === "GET" &&
        pathname === "/api/restaurants"
      ) {
        return await getRestaurants(env);
      }


      if (
        request.method === "GET" &&
        pathname === "/api/places"
      ) {
        return await getPlaces(env);
      }


      if (
        request.method === "POST" &&
        pathname === "/api/business-request"
      ) {
        return await createBusinessRequest(
          request,
          env
        );
      }


      if (pathname.startsWith("/api/")) {

        return error(
          "API endpoint bulunamadı.",
          404
        );

      }


      return env.ASSETS.fetch(request);

    } catch (err) {

      console.error(err);

      return error(
        "Sunucu hatası oluştu.",
        500
      );

    }

  }

};
