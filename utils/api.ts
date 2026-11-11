import AsyncStorage from '@react-native-async-storage/async-storage';

export const API_BASE_URL =
  process.env.EXPO_PUBLIC_API_URL || 'https://ivris.onrender.com';

const TOKEN_KEY = 'ivris_auth_token';

export async function getStoredToken(): Promise<string | null> {
  try {
    return await AsyncStorage.getItem(TOKEN_KEY);
  } catch (_e) {
    return null;
  }
}

export async function setStoredToken(token: string): Promise<void> {
  try {
    await AsyncStorage.setItem(TOKEN_KEY, token);
  } catch (_e) {}
}

export async function removeStoredToken(): Promise<void> {
  try {
    await AsyncStorage.removeItem(TOKEN_KEY);
  } catch (_e) {}
}

export function resolveMediaUrl(url: string | null | undefined): string {
  if (!url) return '';
  if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('data:')) {
    return url;
  }
  const cleanBase = API_BASE_URL.replace(/\/+$/, '');
  const cleanPath = url.startsWith('/') ? url : `/${url}`;
  return `${cleanBase}${cleanPath}`;
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<any> {
  const token = await getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const cleanBase = API_BASE_URL.replace(/\/+$/, '');
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  const fullUrl = `${cleanBase}${cleanPath}`;

  const res = await fetch(fullUrl, {
    ...options,
    headers,
  });

  const contentType = res.headers.get('content-type') || '';
  let data: any = null;
  if (contentType.includes('application/json')) {
    data = await res.json();
  } else {
    data = { text: await res.text() };
  }

  if (!res.ok) {
    const errorMsg = data?.error || `Request failed with status ${res.status}`;
    const err = new Error(errorMsg) as any;
    err.status = res.status;
    err.data = data;
    throw err;
  }

  return data;
}

export async function signUpUser(params: {
  email: string;
  password: string;
  handle: string;
  displayName: string;
}) {
  return await apiFetch('/api/signup', {
    method: 'POST',
    body: JSON.stringify({
      email: params.email,
      password: params.password,
      handle: params.handle,
      display_name: params.displayName,
    }),
  });
}

export async function verifyEmailCode(email: string, code: string) {
  const data = await apiFetch('/api/verify-email', {
    method: 'POST',
    body: JSON.stringify({ email, code }),
  });
  if (data?.token) {
    await setStoredToken(data.token);
  }
  return data;
}

export async function signInUser(emailOrHandle: string, password: string) {
  const data = await apiFetch('/api/signin', {
    method: 'POST',
    body: JSON.stringify({ email: emailOrHandle, password }),
  });
  if (data?.token) {
    await setStoredToken(data.token);
  }
  return data;
}

export async function signOutUser() {
  try {
    await apiFetch('/api/signout', { method: 'POST' });
  } catch (_e) {}
  await removeStoredToken();
}

export async function fetchAppState() {
  return await apiFetch('/api/state');
}

export async function createPost(params: {
  dataUrls: string[];
  caption: string;
  location: string;
  mediaKind: 'photo_post' | 'video_story';
  music?: any;
}) {
  return await apiFetch('/api/posts', {
    method: 'POST',
    body: JSON.stringify({
      data_urls: params.dataUrls,
      caption: params.caption,
      location_label: params.location,
      media_kind: params.mediaKind,
      music: params.music || null,
    }),
  });
}

export async function deletePost(postId: string) {
  return await apiFetch('/api/delete-post', {
    method: 'POST',
    body: JSON.stringify({ post_id: postId }),
  });
}

export async function deleteUserAccount() {
  const res = await apiFetch('/api/delete-account', { method: 'POST' });
  await removeStoredToken();
  return res;
}

export async function updateUserSettings(settings: any) {
  return await apiFetch('/api/update-settings', {
    method: 'POST',
    body: JSON.stringify(settings),
  });
}

export async function toggleConnection(targetId: string, action: 'request' | 'accept' | 'remove') {
  return await apiFetch('/api/connect', {
    method: 'POST',
    body: JSON.stringify({ target_id: targetId, action }),
  });
}

export async function fetchChatMessages(partnerId: string) {
  return await apiFetch(`/api/messages?partner_id=${encodeURIComponent(partnerId)}`);
}

export async function sendChatMessage(recipientId: string, message: string) {
  return await apiFetch('/api/messages', {
    method: 'POST',
    body: JSON.stringify({ recipient_id: recipientId, message }),
  });
}

export async function markPostSeen(postId: string) {
  return await apiFetch('/api/seen', {
    method: 'POST',
    body: JSON.stringify({ post_id: postId }),
  });
}

export async function recordPostView(postId: string) {
  return await apiFetch('/api/view', {
    method: 'POST',
    body: JSON.stringify({ post_id: postId }),
  });
}

export async function applyForInstitution(params: {
  name: string;
  domain: string;
  email: string;
  notes?: string;
}) {
  return await apiFetch('/api/institution-apply', {
    method: 'POST',
    body: JSON.stringify({
      institution_name: params.name,
      official_domain: params.domain,
      contact_email: params.email,
      notes: params.notes || '',
    }),
  });
}

export async function updateUserProfile(params: {
  display_name: string;
  handle: string;
  bio: string;
  avatar_data_url?: string;
  remove_avatar?: boolean;
}) {
  const data = await apiFetch('/api/update-profile', {
    method: 'POST',
    body: JSON.stringify(params),
  });
  if (data?.token) {
    await setStoredToken(data.token);
  }
  return data;
}

export async function reportPostOnServer(postId: string, reason: string) {
  return await apiFetch('/api/report', {
    method: 'POST',
    body: JSON.stringify({
      report_type: 'post',
      post_id: postId,
      reason,
    }),
  });
}

export async function reportAccountOnServer(params: {
  target_user_id: string;
  reason: string;
  block_user?: boolean;
}) {
  return await apiFetch('/api/report', {
    method: 'POST',
    body: JSON.stringify({
      report_type: 'account',
      target_user_id: params.target_user_id,
      reason: params.reason,
      block_user: Boolean(params.block_user),
    }),
  });
}
