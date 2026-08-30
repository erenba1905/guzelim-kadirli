function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}

function error(message, status = 400) {
  return json({
    success: false,
    error: message
  }, status);
}

function isAdmin(request, env) {
  const provided =
    request.headers.get("X-Admin-Password") || "";

  const expected =
    env.ADMIN_PASSWORD || "";

  return (
    expected.length > 0 &&
    provided === expected
  );
}

function requireAdmin(request, env) {
  if (!isAdmin(request, env)) {
    return error("Yetkisiz erişim.", 401);
  }

  return null;
}

function validId(id) {
  const value = Number(id);

  if (
    !Number.isInteger(value) ||
    value < 1
  ) {
    return null;
  }

  return value;
}

/* =================================
   PUBLIC RESTAURANTS
================================= */

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
    restaurants: result.results || []
  });
}

/* =================================
   PUBLIC PLACES
================================= */

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
    places: result.results || []
  });
}

/* =================================
   PUBLIC BUSINESS REQUEST
================================= */

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

  if (businessName.length > 120) {
    return error("İşletme adı çok uzun.");
  }

  if (category.length > 80) {
    return error("Kategori çok uzun.");
  }

  if (phone.length > 40) {
    return error("Telefon bilgisi çok uzun.");
  }

  if (address.length > 300) {
    return error("Adres çok uzun.");
  }

  if (message.length > 1500) {
    return error("Mesaj çok uzun.");
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

  return json({
    success: true,
    id: result.meta.last_row_id,
    message: "Başvurunuz kaydedildi."
  }, 201);
}

/* =================================
   ADMIN REQUESTS
================================= */

async function getAdminRequests(request, env) {
  const denied = requireAdmin(request, env);

  if (denied) {
    return denied;
  }

  const result = await env.DB
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
    requests: result.results || []
  });
}

async function updateAdminRequest(
  request,
  env,
  id
) {
  const denied = requireAdmin(request, env);

  if (denied) {
    return denied;
  }

  const numericId = validId(id);

  if (!numericId) {
    return error("Geçersiz ID.");
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return error("Geçersiz JSON.");
  }

  const status =
    String(body.status || "").trim();

  if (
    ![
      "pending",
      "approved",
      "rejected"
    ].includes(status)
  ) {
    return error("Geçersiz durum.");
  }

  const existing = await env.DB
    .prepare(`
      SELECT id
      FROM business_requests
      WHERE id = ?
    `)
    .bind(numericId)
    .first();

  if (!existing) {
    return error("Başvuru bulunamadı.", 404);
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

async function deleteAdminRequest(
  request,
  env,
  id
) {
  const denied = requireAdmin(request, env);

  if (denied) {
    return denied;
  }

  const numericId = validId(id);

  if (!numericId) {
    return error("Geçersiz ID.");
  }

  await env.DB
    .prepare(`
      DELETE FROM business_requests
      WHERE id = ?
    `)
    .bind(numericId)
    .run();

  return json({
    success: true,
    deleted_id: numericId
  });
}

/* =================================
   ADMIN RESTAURANTS
================================= */

async function getAdminRestaurants(
  request,
  env
) {
  const denied = requireAdmin(request, env);

  if (denied) {
    return denied;
  }

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
        featured,
        active,
        created_at
      FROM restaurants
      ORDER BY featured DESC, id ASC
    `)
    .all();

  return json({
    success: true,
    restaurants: result.results || []
  });
}

function normalizeRestaurant(body) {
  return {
    name:
      String(body.name || "").trim(),

    category:
      String(body.category || "").trim(),

    filter:
      String(body.filter || "").trim(),

    description:
      String(body.description || "").trim(),

    rating:
      Number(body.rating || 0),

    address:
      String(body.address || "").trim(),

    phone:
      String(body.phone || "").trim(),

    hours:
      String(body.hours || "").trim(),

    image:
      String(body.image || "").trim(),

    emoji:
      String(body.emoji || "🍽️").trim(),

    featured:
      body.featured ? 1 : 0,

    active:
      body.active === false ? 0 : 1
  };
}

function validateRestaurant(item) {
  if (!item.name) {
    return "Restoran adı zorunludur.";
  }

  if (!item.category) {
    return "Kategori zorunludur.";
  }

  if (!item.filter) {
    return "Filtre zorunludur.";
  }

  if (
    Number.isNaN(item.rating) ||
    item.rating < 0 ||
    item.rating > 5
  ) {
    return "Puan 0 ile 5 arasında olmalıdır.";
  }

  return null;
}

async function createAdminRestaurant(
  request,
  env
) {
  const denied = requireAdmin(request, env);

  if (denied) {
    return denied;
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return error("Geçersiz JSON.");
  }

  const item =
    normalizeRestaurant(body);

  const validationError =
    validateRestaurant(item);

  if (validationError) {
    return error(validationError);
  }

  const result = await env.DB
    .prepare(`
      INSERT INTO restaurants
      (
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
        featured,
        active
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      item.name,
      item.category,
      item.filter,
      item.description,
      item.rating,
      item.address,
      item.phone,
      item.hours,
      item.image,
      item.emoji,
      item.featured,
      item.active
    )
    .run();

  return json({
    success: true,
    id: result.meta.last_row_id
  }, 201);
}

async function updateAdminRestaurant(
  request,
  env,
  id
) {
  const denied =
    requireAdmin(request, env);

  if (denied) {
    return denied;
  }

  const numericId = validId(id);

  if (!numericId) {
    return error("Geçersiz ID.");
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return error("Geçersiz JSON.");
  }

  const item =
    normalizeRestaurant(body);

  const validationError =
    validateRestaurant(item);

  if (validationError) {
    return error(validationError);
  }

  const existing = await env.DB
    .prepare(`
      SELECT id
      FROM restaurants
      WHERE id = ?
    `)
    .bind(numericId)
    .first();

  if (!existing) {
    return error(
      "Restoran bulunamadı.",
      404
    );
  }

  await env.DB
    .prepare(`
      UPDATE restaurants
      SET
        name = ?,
        category = ?,
        filter = ?,
        description = ?,
        rating = ?,
        address = ?,
        phone = ?,
        hours = ?,
        image = ?,
        emoji = ?,
        featured = ?,
        active = ?
      WHERE id = ?
    `)
    .bind(
      item.name,
      item.category,
      item.filter,
      item.description,
      item.rating,
      item.address,
      item.phone,
      item.hours,
      item.image,
      item.emoji,
      item.featured,
      item.active,
      numericId
    )
    .run();

  return json({
    success: true,
    id: numericId
  });
}

async function deleteAdminRestaurant(
  request,
  env,
  id
) {
  const denied =
    requireAdmin(request, env);

  if (denied) {
    return denied;
  }

  const numericId = validId(id);

  if (!numericId) {
    return error("Geçersiz ID.");
  }

  await env.DB
    .prepare(`
      DELETE FROM restaurants
      WHERE id = ?
    `)
    .bind(numericId)
    .run();

  return json({
    success: true,
    deleted_id: numericId
  });
}

/* =================================
   MAIN
================================= */

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    const pathname =
      url.pathname;

    try {

      /* PUBLIC */

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

      /* ADMIN REQUESTS */

      if (
        request.method === "GET" &&
        pathname === "/api/admin/requests"
      ) {
        return await getAdminRequests(
          request,
          env
        );
      }

      const requestMatch =
        pathname.match(
          /^\/api\/admin\/requests\/(\d+)$/
        );

      if (
        requestMatch &&
        request.method === "PATCH"
      ) {
        return await updateAdminRequest(
          request,
          env,
          requestMatch[1]
        );
      }

      if (
        requestMatch &&
        request.method === "DELETE"
      ) {
        return await deleteAdminRequest(
          request,
          env,
          requestMatch[1]
        );
      }

      /* ADMIN RESTAURANTS */

      if (
        request.method === "GET" &&
        pathname === "/api/admin/restaurants"
      ) {
        return await getAdminRestaurants(
          request,
          env
        );
      }

      if (
        request.method === "POST" &&
        pathname === "/api/admin/restaurants"
      ) {
        return await createAdminRestaurant(
          request,
          env
        );
      }

      const restaurantMatch =
        pathname.match(
          /^\/api\/admin\/restaurants\/(\d+)$/
        );

      if (
        restaurantMatch &&
        request.method === "PATCH"
      ) {
        return await updateAdminRestaurant(
          request,
          env,
          restaurantMatch[1]
        );
      }

      if (
        restaurantMatch &&
        request.method === "DELETE"
      ) {
        return await deleteAdminRestaurant(
          request,
          env,
          restaurantMatch[1]
        );
      }

      /* UNKNOWN API */

      if (
        pathname.startsWith("/api/")
      ) {
        return error(
          "API endpoint bulunamadı.",
          404
        );
      }

      /* STATIC FILES */

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
