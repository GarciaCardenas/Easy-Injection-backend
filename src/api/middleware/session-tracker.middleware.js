const UAParser = require("ua-parser-js");
const geoip = require("geoip-lite");

const createSessionData = (req, sessionId) => {
  const parser = new UAParser(req.headers["user-agent"]);
  const ua = parser.getResult();

  let ip =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.headers["cf-connecting-ip"] ||
    req.headers["true-client-ip"] ||
    req.headers["x-client-ip"] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.connection?.socket?.remoteAddress ||
    "Unknown";

  if (ip.startsWith("::ffff:")) {
    ip = ip.substring(7);
  }
  
  if (ip === "::1" || ip === "127.0.0.1" || ip === "localhost") {
    ip = "127.0.0.1";
  }

  if (ip.includes(":") && !ip.includes("::")) {
    ip = ip.split(":")[0];
  }

  let geo = null;
  let location = "Unknown Location";
  
  if (ip !== "127.0.0.1" && ip !== "Unknown" && ip !== "::1") {
    geo = geoip.lookup(ip);
    if (geo) {
      location = `${geo.city || geo.region || "Unknown City"}, ${geo.country || "Unknown"}`;
    }
  } else if (ip === "127.0.0.1") {
    location = "Localhost (Development)";
  }

  let deviceType = "Desktop";
  if (ua.device.type) {
    deviceType = ua.device.type.charAt(0).toUpperCase() + ua.device.type.slice(1);
  } else if (ua.device.model) {
    deviceType = ua.device.model;
  }

  const browser = `${ua.browser.name || "Unknown"} ${
    ua.browser.version?.split('.')[0] || ""
  }`.trim();

  const os = `${ua.os.name || "Unknown"} ${ua.os.version || ""}`.trim();

  return {
    sessionId,
    ip,
    location,
    device: deviceType,
    browser,
    os,
    lastActivity: new Date(),
    createdAt: new Date()
  };
};

module.exports = { createSessionData };
