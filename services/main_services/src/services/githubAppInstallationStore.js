const { getSupabase } = require('../config/supabase');

// Persists which GitHub App installations exist and which app user connected
// each one — populated by the `installation` webhook event and installCallback.
//
// Expected table:
//   create table if not exists github_app_installations (
//     installation_id bigint primary key,
//     account_login text not null,
//     account_type text not null,
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
  const updatePayload = {
    installation_id: Number(installationId),
    updated_at: new Date().toISOString(),
  };
 
  if (accountLogin) updatePayload.account_login = accountLogin;
  if (accountType) updatePayload.account_type = accountType;
  if (connectedByUserId !== undefined) updatePayload.connected_by_user_id = connectedByUserId || null;
  if (repositorySelection) updatePayload.repository_selection = repositorySelection;

  const { error } = await table().upsert(updatePayload, { onConflict: 'installation_id' });
  if (error) {
    if (error.message && error.message.includes('connected_by_user_id')) {
      delete updatePayload.connected_by_user_id;
      const retry = await table().upsert(updatePayload, { onConflict: 'installation_id' });
      if (retry.error) throw Object.assign(new Error(retry.error.message), { status: 500 });
      return;
    }
    throw Object.assign(new Error(error.message), { status: 500 });
  }
}

async function getInstallationByAccount(accountLogin) {
  const { data, error } = await table().select('*').eq('account_login', accountLogin).maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return data ? _fromRow(data) : null;
}

async function getInstallationById(installationId) {
  const { data, error } = await table().select('*').eq('installation_id', Number(installationId)).maybeSingle();
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
  return data ? _fromRow(data) : null;
}

async function getInstallationForUser(userId) {
  if (!userId) return null;
  try {
    const { data, error } = await table().select('*').eq('connected_by_user_id', userId).order('updated_at', { ascending: false }).limit(1).maybeSingle();
    if (error) {
      if (error.message && error.message.includes('connected_by_user_id')) {
        const fallback = await table().select('*').order('updated_at', { ascending: false }).limit(1).maybeSingle();
        if (fallback.error || !fallback.data) return null;
        return _fromRow(fallback.data);
      }
      return null;
    }
    return data ? _fromRow(data) : null;
  } catch {
    return null;
  }
}

async function listInstallationsForUser(userId) {
  if (!userId) return [];
  try {
    const { data, error } = await table().select('*').eq('connected_by_user_id', userId).order('updated_at', { ascending: false });
    if (error) {
      if (error.message && error.message.includes('connected_by_user_id')) {
        const fallback = await table().select('*').order('updated_at', { ascending: false });
        return (fallback.data || []).map(_fromRow);
      }
      return [];
    }
    return (data || []).map(_fromRow);
  } catch {
    return [];
  }
}

async function deleteInstallation(installationId) {
  const { error } = await table().delete().eq('installation_id', Number(installationId));
  if (error) throw Object.assign(new Error(error.message), { status: 500 });
}

async function deleteInstallationForUser(userId) {
  try {
    await table().delete().eq('connected_by_user_id', userId);
  } catch {
    // Non-fatal if column or row doesn't exist
  }
}

function _fromRow(data) {
  return {
    installationId: data.installation_id,
    accountLogin: data.account_login,
    accountType: data.account_type,
    connectedByUserId: data.connected_by_user_id,
    repositorySelection: data.repository_selection,
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
