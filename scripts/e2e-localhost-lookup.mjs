// Preloaded into the Node processes of a run through Caddy (`node --import`, via NODE_OPTIONS in scripts/ci-web.sh), so
// that `panel.localhost` and `admin.localhost` resolve to the loopback from Playwright's request context and from node:http.
// Chrome does this by itself for every *.localhost name (RFC 6761), and glibc usually does, but the resolver of Windows does
// not, and the run must not edit the hosts file or any system setting. Only a name ending in .localhost is answered here;
// everything else goes to the real lookup, so a typo in a host name still fails and nothing reaches a public address.
import dns from "node:dns";

const isLocalhostName = (name) => typeof name === "string" && /(^|\.)localhost\.?$/i.test(name);
const answer = (options) => {
  const all = typeof options === "object" && options !== null && options.all;
  return all ? [{address: "127.0.0.1", family: 4}] : "127.0.0.1";
};

const realLookup = dns.lookup;
dns.lookup = function lookup(hostname, options, callback) {
  const cb = typeof options === "function" ? options : callback;
  if (isLocalhostName(hostname) && typeof cb === "function") {
    const opts = typeof options === "function" ? undefined : options;
    const result = answer(opts);
    process.nextTick(() => (Array.isArray(result) ? cb(null, result) : cb(null, result, 4)));
    return {};
  }
  return realLookup.apply(this, arguments);
};

const realPromise = dns.promises.lookup;
dns.promises.lookup = function lookup(hostname, options) {
  if (isLocalhostName(hostname)) {
    const result = answer(options);
    return Promise.resolve(Array.isArray(result) ? result : {address: result, family: 4});
  }
  return realPromise.apply(this, arguments);
};
