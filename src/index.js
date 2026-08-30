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


function getAdminPassword(request) {
  return request.headers.get(
    "X-Admin-Password"
  ) || "";
}


function isAdmin(request, env) {
  const provided =
    getAdminPassword(request);

  const expected =
    env.ADMIN_PASSWORD || "";

  return (
    expected.length > 0 &&
    provided === expected
  );
}


function requireAdmin(request, env) {
  if (!isAdmin(request, env)) {
    return error(
      "Yetkisiz erişim.",
      401
    );
  }

  return null;
}


/* =========================
   PUBLIC: RESTAURANTS
========================= */

async function getRestaurants(env) {
  const result =
    await env.DB
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
    restaurants:
      result.results || []
  });
}


/* =========================
   PUBLIC: PLACES
========================= */

async function getPlaces(env) {
  const result =
    await env.DB
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
    places:
      result.results || []
  });
}


/* =========================
   PUBLIC: BUSINESS REQUEST
========================= */

async function createBusinessRequest(
  request,
  env
) {
  let body;

  try {
    body =
      await request.json();
  } catch {
    return error(
      "Geçersiz JSON."
    );
  }


  const businessName =
    String(
      body.business_name || ""
    ).trim();

  const category =
    String(
      body.category || ""
    ).trim();

  const phone =
    String(
      body.phone || ""
    ).trim();

  const address =
    String(
      body.address || ""
    ).trim();

  const message =
    String(
      body.message || ""
    ).trim();


  if (!businessName) {
    return error(
      "İşletme adı zorunludur."
    );
  }


  if (!category) {
    return error(
      "Kategori zorunludur."
    );
  }


  if (businessName.length > 120) {
    return error(
      "İşletme adı çok uzun."
    );
  }


  if (category.length > 80) {
    return error(
      "Kategori çok uzun."
    );
  }


  if (phone.length > 40) {
    return error(
      "Telefon bilgisi çok uzun."
    );
  }


  if (address.length > 300) {
    return error(
      "Adres çok uzun."
    );
  }


  if (message.length > 1500) {
    return error(
      "Mesaj çok uzun."
    );
  }


  const result =
    await env.DB
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
      id:
        result.meta.last_row_id,
      message:
        "Başvurunuz kaydedildi."
    },
    201
  );
}


/* =========================
   ADMIN: LIST REQUESTS
========================= */

async function getAdminRequests(
  request,
  env
) {
  const denied =
    requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }


  const result =
    await env.DB
      .prepare(`
        SELECT
          id,
          business_name,
          category,
          phone,
          address,
          message,
          status,
          created_at
        FROM business_requests
        ORDER BY
          CASE status
            WHEN 'pending' THEN 0
            WHEN 'approved' THEN 1
            WHEN 'rejected' THEN 2
            ELSE 3
          END,
          id DESC
      `)
      .all();


  return json({
    success: true,
    requests:
      result.results || []
  });
}


/* =========================
   ADMIN: UPDATE STATUS
========================= */

async function updateAdminRequest(
  request,
  env,
  id
) {
  const denied =
    requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }


  let body;

  try {
    body =
      await request.json();
  } catch {
    return error(
      "Geçersiz JSON."
    );
  }


  const status =
    String(
      body.status || ""
    ).trim();


  const allowedStatuses =
    [
      "pending",
      "approved",
      "rejected"
    ];


  if (
    !allowedStatuses.includes(
      status
    )
  ) {
    return error(
      "Geçersiz durum."
    );
  }


  const numericId =
    Number(id);


  if (
    !Number.isInteger(
      numericId
    )
    ||
    numericId < 1
  ) {
    return error(
      "Geçersiz ID."
    );
  }


  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM business_requests
        WHERE id = ?
      `)
      .bind(
        numericId
      )
      .first();


  if (!existing) {
    return error(
      "Başvuru bulunamadı.",
      404
    );
  }


  await env.DB
    .prepare(`
      UPDATE business_requests
      SET status = ?
      WHERE id = ?
    `)
    .bind(
      status,
      numericId
    )
    .run();


  return json({
    success: true,
    id: numericId,
    status
  });
}


/* =========================
   ADMIN: DELETE REQUEST
========================= */

async function deleteAdminRequest(
  request,
  env,
  id
) {
  const denied =
    requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }


  const numericId =
    Number(id);


  if (
    !Number.isInteger(
      numericId
    )
    ||
    numericId < 1
  ) {
    return error(
      "Geçersiz ID."
    );
  }


  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM business_requests
        WHERE id = ?
      `)
      .bind(
        numericId
      )
      .first();


  if (!existing) {
    return error(
      "Başvuru bulunamadı.",
      404
    );
  }


  await env.DB
    .prepare(`
      DELETE FROM business_requests
      WHERE id = ?
    `)
    .bind(
      numericId
    )
    .run();


  return json({
    success: true,
    deleted_id:
      numericId
  });
}


/* =========================
   MAIN WORKER
========================= */

export default {

  async fetch(
    request,
    env
  ) {

    const url =
      new URL(
        request.url
      );

    const pathname =
      url.pathname;


    try {

      /* PUBLIC API */

      if (
        request.method === "GET"
        &&
        pathname ===
          "/api/restaurants"
      ) {
        return await getRestaurants(
          env
        );
      }


      if (
        request.method === "GET"
        &&
        pathname ===
          "/api/places"
      ) {
        return await getPlaces(
          env
        );
      }


      if (
        request.method === "POST"
        &&
        pathname ===
          "/api/business-request"
      ) {
        return await createBusinessRequest(
          request,
          env
        );
      }


      /* ADMIN API */

      if (
        request.method === "GET"
        &&
        pathname ===
          "/api/admin/requests"
      ) {
        return await getAdminRequests(
          request,
          env
        );
      }


      const adminRequestMatch =
        pathname.match(
          /^\/api\/admin\/requests\/(\d+)$/
        );


      if (
        adminRequestMatch
        &&
        request.method === "PATCH"
      ) {
        return await updateAdminRequest(
          request,
          env,
          adminRequestMatch[1]
        );
      }


      if (
        adminRequestMatch
        &&
        request.method === "DELETE"
      ) {
        return await deleteAdminRequest(
          request,
          env,
          adminRequestMatch[1]
        );
      }


      /* UNKNOWN API */

      if (
        pathname.startsWith(
          "/api/"
        )
      ) {
        return error(
          "API endpoint bulunamadı.",
          404
        );
      }


      /* STATIC WEBSITE */

      return env.ASSETS.fetch(
        request
      );


    } catch (err) {

      console.error(err);


      return error(
        "Sunucu hatası oluştu.",
        500
      );

    }

  }

};
