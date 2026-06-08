export declare function createEntityApi(supabase: any): {
  get: (path: string) => Promise<any>;
  post: (path: string, body?: any) => Promise<any>;
  patch: (path: string, body?: any) => Promise<any>;
};
