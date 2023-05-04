const createError = require('http-errors');
const { sign } = require('cookie-signature');
const Tokens = require('./tokens');

function getProtectOption(options) {
  if (options !== true && typeof options !== "object") {
    return undefined;
  }

  const opts = Object.create(null);

  // defaults
  opts.key = "xcsrf";
  opts.path = "/";

  if (options && typeof options === "object") {
    const o = Object.entries(options);
    for (let i = 0; i < o.length; ++i) {
      const [key, value] = o[i];
      if (value !== undefined) opts[key] = value;
    }
  }

  return opts;
}

function defaultValue(req) {
  // eslint-disable-next-line no-underscore-dangle
  return (
    (req.body && req.body._csrf) ||
    (req.query && req.query._csrf) ||
    req.headers["csrf-token"]
  );
}

function getIgnoredMethods(methods) {
  const obj = Object.create(null);

  for (let i = 0; i < methods.length; i++) {
    const method = methods[i].toUpperCase();
    obj[method] = true;
  }

  return obj;
}

function getSecretBag(req, sessionKey, protect) {
  const csrfToken = req.headers?.xcsrf;
  if (csrfToken) {
    return {
      xcsrf: csrfToken,
    };
  }
  // get secret from session
  return {
    session: true,
  };
}

function getSecret(req, sessionKey, protect) {
  // get the bag & key
  const bag = getSecretBag(req, sessionKey, protect);
  const key = protect ? protect.key : "csrfSecret";

  if (!bag) {
    throw new Error("misconfigured csrf");
  }

  // return secret from bag
  return bag[key];
}

function setHeaderSecret(
  res,
  val,
) {
  res.setHeader("xcsrf", String(val));
}

function setSecret(req, res, sessionKey, val, secret) {
  if (secret) {
    // set secret on secret
    let value = val;

    if (secret.signed) {
      value = `s:${sign(val, req.secret)}`;
    }

    setHeaderSecret(res, value);
  } else {
    // set secret on session
    req[sessionKey].csrfSecret = val;
  }
}

function verifyConfiguration(req, sessionKey, secret) {
  if (!getSecretBag(req, sessionKey, secret)) {
    return false;
  }

  if (secret && secret.signed && !req.secret) {
    return false;
  }

  return true;
}

function csrfProtect(options) {
  const opts = options || {};

  // get protect options
  const protect = getProtectOption(opts.protect);

  // get session options
  const sessionKey = opts.sessionKey || "session";

  // get value getter
  const value = opts.value || defaultValue;

  // token repo
  const tokens = new Tokens(opts);

  // ignored methods
  const ignoreMethods =
    opts.ignoreMethods === undefined
      ? ["GET", "HEAD", "OPTIONS"]
      : opts.ignoreMethods;

  if (!Array.isArray(ignoreMethods)) {
    throw new TypeError("option ignoreMethods must be an array");
  }

  // generate lookup
  const ignoreMethod = getIgnoredMethods(ignoreMethods);

  return function csrf(req, res, next) {
    // validate the configuration against request
    if (!verifyConfiguration(req, sessionKey, protect)) {
      return next(new Error("misconfigured csrf"));
    }

    // get the secret from the request
    let secret = getSecret(req, sessionKey, protect);
    let token;

    // lazy-load token getter
    req.csrfToken = function csrfToken() {
      let sec = !protect ? getSecret(req, sessionKey, protect) : secret;

      // use cached token if secret has not changed
      if (token && sec === secret) {
        return token;
      }

      // generate & set new secret
      if (sec === undefined) {
        sec = tokens.secretSync();
        setSecret(req, res, sessionKey, sec, protect);
      }

      // update changed secret
      secret = sec;

      // create new token
      token = tokens.create(secret);

      return token;
    };

    // generate & set secret
    if (!secret) {
      secret = tokens.secretSync();
      setSecret(req, res, sessionKey, secret, protect);
    }

    // verify the incoming token
    if (!ignoreMethod[req.method] && !tokens.verify(secret, value(req))) {
      return next(
        createError(403, "invalid csrf token", {
          code: "EBADCSRFTOKEN",
        })
      );
    }

    return next();
  };
}

module.exports = csrfProtect;