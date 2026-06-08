export declare const API_BASE: string;
export declare function createAuthenticatedApi(supabase: any): {
  get: (path: string) => Promise<any>;
  post: (path: string, body?: any) => Promise<any>;
  patch: (path: string, body?: any) => Promise<any>;
};
