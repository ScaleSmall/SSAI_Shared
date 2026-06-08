export declare const LDP_EF_BASE: string;
export declare function createLdpApi(supabase: any): {
  getHealth: (entityId: string) => Promise<any>;
  getCorrection: (correctionId: string) => Promise<any>;
  syncLocation: (entityId: string, canonical: any) => Promise<any>;
  setSuppressedAddress: (entityId: string, address: any) => Promise<any>;
};
