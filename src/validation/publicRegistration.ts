/** Public Identity registration is client-only; staff provisioning is trusted-only. */
import { z } from "zod";
import { passwordSchema } from "@hollis-studio/contracts/password";

export const publicRegisterBodySchema = z.object({
  email: z.string().email("Valid email required"),
  password: passwordSchema,
  displayName: z.string().trim().min(1).max(128).optional(),
  role: z.literal("CLIENT").optional(),
  sourceApp: z.string().trim().min(1).max(64).optional(),
});
