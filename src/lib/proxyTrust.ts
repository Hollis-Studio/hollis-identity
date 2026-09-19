import type { Express } from "express";

export function configureProxyTrust(app: Express, nodeEnv: string): void {
  // Production tasks accept port 4001 ONLY from the shared ALB security group
  // (infrastructure/network.tf). The ALB appends the real peer to XFF. Trust
  // exactly that hop, never client-supplied entries to its left. Keep this
  // boundary in sync if ingress topology changes; direct local servers trust none.
  app.set("trust proxy", nodeEnv === "production" ? 1 : false);
}
