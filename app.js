import { app, errorHandler } from "mu";
import {
  getSessionIdHeader,
  getSessionRoles,
  updateActiveRole,
  getActiveSessionRole,
  destroyActiveSessionRole,
  error,
} from "./lib/utils";

app.get("/list", async function(req, res, next) {
  const sessionUri = getSessionIdHeader(req);
  if (!sessionUri) return error(res, "Session header is missing");

  try {
    const roles = await getSessionRoles(sessionUri);
    if (!roles.length) return error(res, "Invalid session: No role available");

    return res.status(200).send(roles);
  } catch (e) {
    return next(new Error(e.message));
  }
});

app.get("/current", async function(req, res, next) {
  const sessionUri = getSessionIdHeader(req);
  if (!sessionUri) return error(res, "Session header is missing");

  try {
    const activeRole = await getActiveSessionRole(sessionUri);

    return res.status(200).send({ activeRole: activeRole });
  } catch (e) {
    return next(new Error(e.message));
  }
});

app.post("/destroy", async function(req, res, next) {
  const sessionUri = getSessionIdHeader(req);
  if (!sessionUri) return error(res, "Session header is missing");

  try {
    await destroyActiveSessionRole(sessionUri);

    return res.header('mu-auth-allowed-groups', 'CLEAR').status(200).send({});
  } catch (e) {
    console.error("Err: ", e);
    return next(new Error(e.message));
  }
});

app.post("/update", async function(req, res, next) {
  const sessionUri = getSessionIdHeader(req);

  if (!sessionUri) return error(res, "Session header is missing");

  try {
    const role = req.query.role;
    const roles = await getSessionRoles(sessionUri);
    if (!roles.length) return error(res, "Invalid session: No role available");
    console.log("Role: ", role);
    console.log("Roles: ", roles);
    if (!roles.includes(role)) return error(res, "Invalid role");

    await updateActiveRole(sessionUri, role);

    return res.header('mu-auth-allowed-groups', 'CLEAR').status(200).send({});
  } catch (e) {
    return next(new Error(e.message));
  }
});

app.use(errorHandler);
