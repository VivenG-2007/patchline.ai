const { getSupabase } = require('../config/supabase');

// Persists the "PatchLine is watching this repo" registry — the source of
// truth for the three-state push gate in githubController.handleWebhook:
//
//   not registered here               -> ignore every push
//   registered, autoRescan = false    -> ignore pushes (manual "Scan Now" still works)
//   registered, autoRescan = true     -> a push to the tracked branch triggers a rescan
//
// Keyed by GitHub's own numeric repository id (not owner/name, which can be
// renamed) so a push webhook — which only carries `repository.id` — can look
// itself up in one query.
//
// Expected table (create once in Supabase SQL editor):
//   create table watched_repositories (
//     repository_id text primary key,        -- GitHub's numeric repo id, as a string
//     user_id text not null,                 -- app user who registered/owns this watch
//     github_repo text not null,             -- "owner/name"
//     branch text not null default 'main',
//     installation_id text,                  -- kept for schema parity with a future GitHub App migration; unused/null under the current OAuth App flow
//     webhook_id text,                       -- GitHub's numeric hook id, for delete + idempotent re-create
//     webhook_active boolean not null default false,
//     auto_rescan boolean not null default true,
//     last_scan_id text,
//     last_scanned_commit text,
//     findings_count integer,
//     created_at timestamptz default now(),
//     updated_at timestamptz default now()
//   );

function table() {
  const supabase = getSupabase();
  if (!supabase) {
    const err = new Error('Supabase not configured — required for the watched-repository registry');
    err.status = 503;
    throw err;
  }
  return supabase.from('watched_repositories');
}

function toModel(row) {
  if (!row) return null;
  return {
    repositoryId: row.repository_id,
    userId: row.user_id,
    githubRepo: row.github_repo,
    branch: row.branch,
    installationId: row.installation_id,
    webhookId: row.webhook_id,
    webhookActive: row.webhook_active,
    autoRescan: row.auto_rescan,
    lastScanId: row.last_scan_id,
    lastScannedCommit: row.last_scanned_commit,
    findingsCount: row.findings_count,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function getByRepositoryId(repositoryId) {
  const { data, error } = await table().select('*').eq('repository_id', String(repositoryId)).maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return toModel(data);
}

async function listForUser(userId) {
  const { data, error } = await table().select('*').eq('user_id', userId).order('updated_at', { ascending: false });
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return (data || []).map(toModel);
}

async function upsertWatch({
  userId,
  repositoryId,
  githubRepo,
  branch = 'main',
  installationId = null,
  webhookId,
  webhookActive = true,
  autoRescan = true,
}) {
  const { data, error } = await table()
    .upsert(
      {
        repository_id: String(repositoryId),
        user_id: userId,
        github_repo: githubRepo,
        branch,
        installation_id: installationId,
        webhook_id: webhookId != null ? String(webhookId) : null,
        webhook_active: webhookActive,
        auto_rescan: autoRescan,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'repository_id' }
    )
    .select('*')
    .maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return toModel(data);
}

async function updateSettings(repositoryId, { autoRescan }) {
  const { data, error } = await table()
    .update({ auto_rescan: autoRescan, updated_at: new Date().toISOString() })
    .eq('repository_id', String(repositoryId))
    .select('*')
    .maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return toModel(data);
}

// Called by workers/scannerWorkers.js once a scan job completes — this is
// what makes the repository-page dashboard (Last Scan / Findings) update
// itself after a webhook-triggered push rescan, without the browser having
// to be open or polling for it.
async function recordScanResult(repositoryId, { lastScanId, lastScannedCommit, findingsCount }) {
  const patch = { updated_at: new Date().toISOString() };
  if (lastScanId !== undefined) patch.last_scan_id = lastScanId;
  if (lastScannedCommit) patch.last_scanned_commit = lastScannedCommit;
  if (findingsCount !== undefined) patch.findings_count = findingsCount;

  const { data, error } = await table().update(patch).eq('repository_id', String(repositoryId)).select('*').maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return toModel(data);
}

async function deleteWatch(repositoryId) {
  const { error } = await table().delete().eq('repository_id', String(repositoryId));
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
}

module.exports = {
  getByRepositoryId,
  listForUser,
  upsertWatch,
  updateSettings,
  recordScanResult,
  deleteWatch,
};
