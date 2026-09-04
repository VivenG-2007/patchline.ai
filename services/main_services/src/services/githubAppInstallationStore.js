const { getSupabase } = require('../config/supabase');

// Persists which GitHub App installations exist and which app user connected
// each one — populated by the `installation` webhook event and installCallback.
//
// Expected table:
//   create table if not exists github_app_installations (
//     installation_id bigint primary key,
//     account_login text not null default '',
//     account_type text not null default 'User',
//     connected_by_user_id text,
//     repository_selection text,
//     created_at timestamptz default now(),
//     updated_at timestamptz default now()
//   );

function table() {
  const supabase = getSupabase();
  if (!supabase) {
    const err = new Error('Supabase not configured — required for storing GitHub App installations');
    err.status = 503;
    throw err;
  }
  return supabase.from('github_app_installations');
}

async function upsertInstallation({ installationId, accountLogin, accountType, connectedByUserId, repositorySelection }) {
  const payload = {
    installation_id: Number(installationId),
    updated_at: new Date().toISOString(),
  };

  if (accountLogin) payload.account_login = accountLogin;
  if (accountType) payload.account_type = accountType;
  if (connectedByUserId !== undefined) payload.connected_by_user_id = connectedByUserId || null;
  if (repositorySelection) payload.repository_selection = repositorySelection;

  try {
    const { error } = await table().upsert(payload, { onConflict: 'installation_id' });
    if (!error) return;

    // If PostgREST schema cache error mentions a missing column, try fallback with only core columns
    if (error.message && (error.message.includes('column') || error.message.includes('schema cache'))) {
      const minimalPayload = {
        installation_id: Number(installationId),
        updated_at: new Date().toISOString(),
      };
      if (accountLogin) minimalPayload.account_login = accountLogin;
      if (accountType) minimalPayload.account_type = accountType;

      const retry = await table().upsert(minimalPayload, { onConflict: 'installation_id' });
      if (retry.error) {
        // Last-ditch attempt: only installation_id
        await table().upsert({ installation_id: Number(installationId) }, { onConflict: 'installation_id' }).catch(() => {});
      }
      return;
    }
    throw Object.assign(new Error(error.message), { status: 500 });
  } catch (err) {
    // If it's a schema cache error, do not crash the webhook handler
    if (err.message && (err.message.includes('column') || err.message.includes('schema cache'))) {
      return;
    }
    throw err;
  }
}

async function getInstallationByAccount(accountLogin) {
  try {
    const { data, error } = await table().select('*').eq('account_login', accountLogin).maybeSingle();
    if (error) return null;
    return data ? _fromRow(data) : null;
  } catch {
    return null;
  }
}

async function getInstallationById(installationId) {
  try {
    const { data, error } = await table().select('*').eq('installation_id', Number(installationId)).maybeSingle();
    if (error) return null;
    return data ? _fromRow(data) : null;
  } catch {
    return null;
  }
}

async function getInstallationForUser(userId) {
  if (!userId) return null;
  try {
    const { data, error } = await table().select('*').eq('connected_by_user_id', userId).order('updated_at', { ascending: false }).limit(1).maybeSingle();
    if (error) {
      const fallback = await table().select('*').order('updated_at', { ascending: false }).limit(1).maybeSingle();
      if (fallback.error || !fallback.data) return null;
      return _fromRow(fallback.data);
    }
    if (data) return _fromRow(data);

    // If no record found with connected_by_user_id, check if there's any active installation
    const fallback = await table().select('*').order('updated_at', { ascending: false }).limit(1).maybeSingle();
    return (fallback.data && !fallback.error) ? _fromRow(fallback.data) : null;
  } catch {
    return null;
  }
}

async function listInstallationsForUser(userId) {
  if (!userId) return [];
  try {
    const { data, error } = await table().select('*').eq('connected_by_user_id', userId).order('updated_at', { ascending: false });
    if (error || !data || data.length === 0) {
      const fallback = await table().select('*').order('updated_at', { ascending: false });
      return (fallback.data || []).map(_fromRow);
    }
    return (data || []).map(_fromRow);
  } catch {
    return [];
  }
}

async function deleteInstallation(installationId) {
  try {
    await table().delete().eq('installation_id', Number(installationId));
  } catch {
    // Non-fatal
  }
}

async function deleteInstallationForUser(userId) {
  try {
    await table().delete().eq('connected_by_user_id', userId);
  } catch {
    // Non-fatal
  }
}

function _fromRow(data) {
  return {
    installationId: data.installation_id,
    accountLogin: data.account_login || 'connected-account',
    accountType: data.account_type || 'User',
    connectedByUserId: data.connected_by_user_id,
    repositorySelection: data.repository_selection || 'all',
  };
}

module.exports = {
  upsertInstallation,
  getInstallationByAccount,
  getInstallationById,
  getInstallationForUser,
  listInstallationsForUser,
  deleteInstallation,
  deleteInstallationForUser,
};
