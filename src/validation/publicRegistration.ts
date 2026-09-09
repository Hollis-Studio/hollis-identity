/** Public Identity registration is client-only; staff provisioning is trusted-only. */
import { z } from "zod";

export const publicRegisterBodySchema = z.object({
  email: z.string().email("Valid email required"),
  password: z.string().min(6, "Password must be at least 6 characters").max(128, "Password must be at most 128 characters"),
  displayName: z.string().trim().min(1).max(128).optional(),
  role: z.literal("CLIENT").optional(),
  sourceApp: z.string().trim().min(1).max(64).optional(),
});
