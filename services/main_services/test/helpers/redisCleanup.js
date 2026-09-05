// Test-only helper. Production shutdown (src/server.js) already has its own
// 10s force-exit failsafe (setTimeout(() => process.exit(1), 10000).unref())
// for exactly this class of problem, so this isn't a production bug — it's
// specifically that `node --test` waits for the event loop to drain with NO
// failsafe of its own, so a real ioredis client's `.quit()` against a
// Redis that was never actually reachable (no server running, as in CI/this
// sandbox) can hang the test run forever: `.quit()` sends the QUIT command
// over the wire and waits for a reply, but with `maxRetriesPerRequest: null`
// (required by both config/redis.js and config/queue.js — BullMQ mandates it)
// there's no reply ever coming and no retry ceiling to give up at.
//
// `.disconnect()` (as opposed to `.quit()`) is synchronous/immediate — it
// just tears the socket down without waiting for a server reply — so racing
// quit() against a short timeout that falls back to disconnect() gets a
// clean exit whether or not Redis is actually there.
async function quitOrDisconnect(client, timeoutMs = 1500) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(resolve, timeoutMs);
  });
  try {
    await Promise.race([client.quit().catch(() => {}), timeout]);
  } finally {
    clearTimeout(timer);
    // Idempotent — calling disconnect() on an already-closed client is a
    // no-op in ioredis, so it's safe to always call this rather than track
    // whether quit() actually won the race.
    client.disconnect();
  }
}

module.exports = { quitOrDisconnect };
