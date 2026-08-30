function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers
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

function textToBytes(value) {
  return new TextEncoder().encode(value);
}

function bytesToBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64UrlToBytes(value) {
  const normalized =
    value
      .replaceAll("-", "+")
      .replaceAll("_", "/");

  const padding =
    "=".repeat(
      (4 - normalized.length % 4) % 4
    );

  const binary =
    atob(normalized + padding);

  return Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );
}

async function hmacSign(
  value,
  secret
) {
  const key =
    await crypto.subtle.importKey(
      "raw",
      textToBytes(secret),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      key,
      textToBytes(value)
    );

  return bytesToBase64Url(
    new Uint8Array(signature)
  );
}

async function hmacVerify(
  value,
  signature,
  secret
) {
  try {
    const key =
      await crypto.subtle.importKey(
        "raw",
        textToBytes(secret),
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["verify"]
      );

    return await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlToBytes(signature),
      textToBytes(value)
    );
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const cookieHeader =
    request.headers.get("Cookie") || "";

  const cookies =
    cookieHeader
      .split(";")
      .map(item => item.trim());

  for (const cookie of cookies) {
    const separator =
      cookie.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const key =
      cookie.slice(0, separator);

    const value =
      cookie.slice(separator + 1);

    if (key === name) {
      return value;
    }
  }

  return "";
}

async function createSession(env) {
  const expiresAt =
    Date.now() +
    8 * 60 * 60 * 1000;

  const payloadObject = {
    role: "admin",
    exp: expiresAt
  };

  const payload =
    bytesToBase64Url(
      textToBytes(
        JSON.stringify(
          payloadObject
        )
      )
    );

  const signature =
    await hmacSign(
      payload,
      env.SESSION_SECRET
    );

  return `${payload}.${signature}`;
}

async function verifySession(
  request,
  env
) {
  if (!env.SESSION_SECRET) {
    return false;
  }

  const session =
    getCookie(
      request,
      "admin_session"
    );

  if (!session) {
    return false;
  }

  const parts =
    session.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const [
    payload,
    signature
  ] = parts;

  const validSignature =
    await hmacVerify(
      payload,
      signature,
      env.SESSION_SECRET
    );

  if (!validSignature) {
    return false;
  }

  try {
    const payloadBytes =
      base64UrlToBytes(payload);

    const payloadText =
      new TextDecoder()
        .decode(payloadBytes);

    const data =
      JSON.parse(payloadText);

    if (
      data.role !== "admin" ||
      !data.exp ||
      Date.now() > data.exp
    ) {
      return false;
    }

    return true;

  } catch {
    return false;
  }
}

async function requireAdmin(
  request,
  env
) {
  const valid =
    await verifySession(
      request,
      env
    );

  if (!valid) {
    return error(
      "Yetkisiz erişim.",
      401
    );
  }

  return null;
}

async function passwordsMatch(
  provided,
  expected
) {
  if (!provided || !expected) {
    return false;
  }

  const providedHash =
    await crypto.subtle.digest(
      "SHA-256",
      textToBytes(provided)
    );

  const expectedHash =
    await crypto.subtle.digest(
      "SHA-256",
      textToBytes(expected)
    );

  const a =
    new Uint8Array(
      providedHash
    );

  const b =
    new Uint8Array(
      expectedHash
    );

  if (a.length !== b.length) {
    return false;
  }

  let difference = 0;

  for (
    let i = 0;
    i < a.length;
    i++
  ) {
    difference |=
      a[i] ^ b[i];
  }

  return difference === 0;
}

/* =====================================
   ADMIN LOGIN
===================================== */

async function adminLogin(
  request,
  env
) {
  if (
    !env.ADMIN_PASSWORD ||
    !env.SESSION_SECRET
  ) {
    return error(
      "Admin güvenliği yapılandırılmamış.",
      500
    );
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

  const password =
    String(
      body.password || ""
    );

  const valid =
    await passwordsMatch(
      password,
      env.ADMIN_PASSWORD
    );

  if (!valid) {
    return error(
      "Şifre yanlış.",
      401
    );
  }

  const session =
    await createSession(env);

  return json(
    {
      success: true
    },
    200,
    {
      "Set-Cookie":
        `admin_session=${session}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
    }
  );
}

async function adminLogout() {
  return json(
    {
      success: true
    },
    200,
    {
      "Set-Cookie":
        "admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
    }
  );
}

async function adminSession(
  request,
  env
) {
  const valid =
    await verifySession(
      request,
      env
    );

  return json({
    success: true,
    authenticated: valid
  });
}

/* =====================================
   PUBLIC RESTAURANTS
===================================== */

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

/* =====================================
   PUBLIC PLACES
===================================== */

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

/* =====================================
   PUBLIC BUSINESS REQUEST
===================================== */

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

/* =====================================
   ADMIN REQUESTS
===================================== */

async function getAdminRequests(
  request,
  env
) {
  const denied =
    await requireAdmin(
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

async function approveAdminRequest(
  request,
  env,
  id
) {
  const denied =
    await requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }

  const numericId =
    validId(id);

  if (!numericId) {
    return error(
      "Geçersiz ID."
    );
  }

  const application =
    await env.DB
      .prepare(`
        SELECT *
        FROM business_requests
        WHERE id = ?
      `)
      .bind(numericId)
      .first();

  if (!application) {
    return error(
      "Başvuru bulunamadı.",
      404
    );
  }

  if (
    application.status ===
    "approved"
  ) {
    return error(
      "Bu başvuru zaten onaylanmış."
    );
  }

  const normalizedCategory =
    String(
      application.category || ""
    ).toLocaleLowerCase(
      "tr-TR"
    );

  const isRestaurant =
    normalizedCategory.includes(
      "restoran"
    );

  const isCafe =
    normalizedCategory.includes(
      "cafe"
    );

  let createdRestaurant =
    false;

  if (
    isRestaurant ||
    isCafe
  ) {
    const existing =
      await env.DB
        .prepare(`
          SELECT id
          FROM restaurants
          WHERE LOWER(name) = LOWER(?)
          LIMIT 1
        `)
        .bind(
          application.business_name
        )
        .first();

    if (!existing) {
      const filter =
        isCafe
          ? "cafe"
          : "lokanta";

      const category =
        isCafe
          ? "Cafe"
          : "Restaurant";

      const emoji =
        isCafe
          ? "☕"
          : "🍽️";

      await env.DB
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
          application.business_name,
          category,
          filter,
          application.message || "",
          0,
          application.address || "",
          application.phone || "",
          "Bilgi doğrulanacak",
          "",
          emoji,
          0,
          1
        )
        .run();

      createdRestaurant =
        true;
    }
  }

  await env.DB
    .prepare(`
      UPDATE business_requests
      SET status = 'approved'
      WHERE id = ?
    `)
    .bind(numericId)
    .run();

  return json({
    success: true,
    id: numericId,
    status: "approved",
    restaurant_created:
      createdRestaurant
  });
}

async function updateAdminRequest(
  request,
  env,
  id
) {
  const denied =
    await requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }

  const numericId =
    validId(id);

  if (!numericId) {
    return error(
      "Geçersiz ID."
    );
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

  if (
    ![
      "pending",
      "rejected"
    ].includes(status)
  ) {
    return error(
      "Geçersiz durum."
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

async function deleteAdminRequest(
  request,
  env,
  id
) {
  const denied =
    await requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }

  const numericId =
    validId(id);

  if (!numericId) {
    return error(
      "Geçersiz ID."
    );
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
    deleted_id:
      numericId
  });
}

/* =====================================
   ADMIN RESTAURANTS
===================================== */

async function getAdminRestaurants(
  request,
  env
) {
  const denied =
    await requireAdmin(
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
    restaurants:
      result.results || []
  });
}

function normalizeRestaurant(body) {
  return {
    name:
      String(
        body.name || ""
      ).trim(),

    category:
      String(
        body.category || ""
      ).trim(),

    filter:
      String(
        body.filter || ""
      ).trim(),

    description:
      String(
        body.description || ""
      ).trim(),

    rating:
      Number(
        body.rating || 0
      ),

    address:
      String(
        body.address || ""
      ).trim(),

    phone:
      String(
        body.phone || ""
      ).trim(),

    hours:
      String(
        body.hours || ""
      ).trim(),

    image:
      String(
        body.image || ""
      ).trim(),

    emoji:
      String(
        body.emoji || "🍽️"
      ).trim(),

    featured:
      body.featured ? 1 : 0,

    active:
      body.active === false
        ? 0
        : 1
  };
}

function validateRestaurant(
  item
) {
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
    Number.isNaN(
      item.rating
    ) ||
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
  const denied =
    await requireAdmin(
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

  const item =
    normalizeRestaurant(body);

  const validationError =
    validateRestaurant(item);

  if (validationError) {
    return error(
      validationError
    );
  }

  const result =
    await env.DB
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

  return json(
    {
      success: true,
      id:
        result.meta.last_row_id
    },
    201
  );
}

async function updateAdminRestaurant(
  request,
  env,
  id
) {
  const denied =
    await requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }

  const numericId =
    validId(id);

  if (!numericId) {
    return error(
      "Geçersiz ID."
    );
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

  const item =
    normalizeRestaurant(body);

  const validationError =
    validateRestaurant(item);

  if (validationError) {
    return error(
      validationError
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
    await requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }

  const numericId =
    validId(id);

  if (!numericId) {
    return error(
      "Geçersiz ID."
    );
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
    deleted_id:
      numericId
  });
}

/* =====================================
   ADMIN PLACES
===================================== */

async function getAdminPlaces(
  request,
  env
) {
  const denied =
    await requireAdmin(
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
          name,
          category,
          description,
          address,
          image,
          emoji,
          active,
          created_at
        FROM places
        ORDER BY id ASC
      `)
      .all();

  return json({
    success: true,
    places:
      result.results || []
  });
}

function normalizePlace(body) {
  return {
    name:
      String(
        body.name || ""
      ).trim(),

    category:
      String(
        body.category || ""
      ).trim(),

    description:
      String(
        body.description || ""
      ).trim(),

    address:
      String(
        body.address || ""
      ).trim(),

    image:
      String(
        body.image || ""
      ).trim(),

    emoji:
      String(
        body.emoji || "📍"
      ).trim(),

    active:
      body.active === false
        ? 0
        : 1
  };
}

function validatePlace(item) {
  if (!item.name) {
    return "Yer adı zorunludur.";
  }

  if (!item.category) {
    return "Kategori zorunludur.";
  }

  return null;
}

async function createAdminPlace(
  request,
  env
) {
  const denied =
    await requireAdmin(
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

  const item =
    normalizePlace(body);

  const validationError =
    validatePlace(item);

  if (validationError) {
    return error(
      validationError
    );
  }

  const result =
    await env.DB
      .prepare(`
        INSERT INTO places
        (
          name,
          category,
          description,
          address,
          image,
          emoji,
          active
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        item.name,
        item.category,
        item.description,
        item.address,
        item.image,
        item.emoji,
        item.active
      )
      .run();

  return json(
    {
      success: true,
      id:
        result.meta.last_row_id
    },
    201
  );
}

async function updateAdminPlace(
  request,
  env,
  id
) {
  const denied =
    await requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }

  const numericId =
    validId(id);

  if (!numericId) {
    return error(
      "Geçersiz ID."
    );
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

  const item =
    normalizePlace(body);

  const validationError =
    validatePlace(item);

  if (validationError) {
    return error(
      validationError
    );
  }

  await env.DB
    .prepare(`
      UPDATE places
      SET
        name = ?,
        category = ?,
        description = ?,
        address = ?,
        image = ?,
        emoji = ?,
        active = ?
      WHERE id = ?
    `)
    .bind(
      item.name,
      item.category,
      item.description,
      item.address,
      item.image,
      item.emoji,
      item.active,
      numericId
    )
    .run();

  return json({
    success: true,
    id: numericId
  });
}

async function deleteAdminPlace(
  request,
  env,
  id
) {
  const denied =
    await requireAdmin(
      request,
      env
    );

  if (denied) {
    return denied;
  }

  const numericId =
    validId(id);

  if (!numericId) {
    return error(
      "Geçersiz ID."
    );
  }

  await env.DB
    .prepare(`
      DELETE FROM places
      WHERE id = ?
    `)
    .bind(numericId)
    .run();

  return json({
    success: true,
    deleted_id:
      numericId
  });
}

/* =====================================
   MAIN
===================================== */

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

      /* ADMIN AUTH */

      if (
        request.method === "POST" &&
        pathname ===
          "/api/admin/login"
      ) {
        return await adminLogin(
          request,
          env
        );
      }

      if (
        request.method === "POST" &&
        pathname ===
          "/api/admin/logout"
      ) {
        return await adminLogout();
      }

      if (
        request.method === "GET" &&
        pathname ===
          "/api/admin/session"
      ) {
        return await adminSession(
          request,
          env
        );
      }

      /* PUBLIC */

      if (
        request.method === "GET" &&
        pathname ===
          "/api/restaurants"
      ) {
        return await getRestaurants(
          env
        );
      }

      if (
        request.method === "GET" &&
        pathname ===
          "/api/places"
      ) {
        return await getPlaces(
          env
        );
      }

      if (
        request.method === "POST" &&
        pathname ===
          "/api/business-request"
      ) {
        return await createBusinessRequest(
          request,
          env
        );
      }

      /* ADMIN REQUESTS */

      if (
        request.method === "GET" &&
        pathname ===
          "/api/admin/requests"
      ) {
        return await getAdminRequests(
          request,
          env
        );
      }

      const approveMatch =
        pathname.match(
          /^\/api\/admin\/requests\/(\d+)\/approve$/
        );

      if (
        approveMatch &&
        request.method === "POST"
      ) {
        return await approveAdminRequest(
          request,
          env,
          approveMatch[1]
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
        pathname ===
          "/api/admin/restaurants"
      ) {
        return await getAdminRestaurants(
          request,
          env
        );
      }

      if (
        request.method === "POST" &&
        pathname ===
          "/api/admin/restaurants"
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

      /* ADMIN PLACES */

      if (
        request.method === "GET" &&
        pathname ===
          "/api/admin/places"
      ) {
        return await getAdminPlaces(
          request,
          env
        );
      }

      if (
        request.method === "POST" &&
        pathname ===
          "/api/admin/places"
      ) {
        return await createAdminPlace(
          request,
          env
        );
      }

      const placeMatch =
        pathname.match(
          /^\/api\/admin\/places\/(\d+)$/
        );

      if (
        placeMatch &&
        request.method === "PATCH"
      ) {
        return await updateAdminPlace(
          request,
          env,
          placeMatch[1]
        );
      }

      if (
        placeMatch &&
        request.method === "DELETE"
      ) {
        return await deleteAdminPlace(
          request,
          env,
          placeMatch[1]
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
