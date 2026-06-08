import { createAuthenticatedApi } from './api.js';

export function createEntityApi(supabase) {
  return createAuthenticatedApi(supabase);
}
