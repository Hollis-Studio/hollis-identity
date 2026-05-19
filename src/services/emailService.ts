/**
 * @ai-context Email Service | outbound transactional email boundary for Identity
 *
 * Sends password reset messages through SES in production. Console mode remains
 * available for local development without external infrastructure.
 */

import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { getEnv } from "../lib/env";
import { logger } from "../lib/logger";

let sesClient: SESv2Client | null = null;

function getSesClient(): SESv2Client {
  if (sesClient) return sesClient;
  const env = getEnv();
  sesClient = new SESv2Client({ region: env.AWS_REGION });
  return sesClient;
}

function buildResetUrl(token: string): string {
  const env = getEnv();
  if (!env.RESET_PASSWORD_URL) {
    throw new Error("RESET_PASSWORD_URL is required to send password reset email");
  }

  const url = new URL(env.RESET_PASSWORD_URL);
  url.searchParams.set("token", token);
  return url.toString();
}

export async function sendPasswordResetEmail(params: {
  email: string;
  token: string;
  expiresAt: Date;
}): Promise<void> {
  const env = getEnv();
  const resetUrl = buildResetUrl(params.token);

  if (env.EMAIL_PROVIDER === "console") {
    logger.info(
      { email: params.email, resetUrl, expiresAt: params.expiresAt },
      "Password reset email console delivery",
    );
    return;
  }

  await getSesClient().send(new SendEmailCommand({
    FromEmailAddress: env.EMAIL_FROM,
    Destination: {
      ToAddresses: [params.email],
    },
    Content: {
      Simple: {
        Subject: {
          Data: "Reset your Hollis password",
          Charset: "UTF-8",
        },
        Body: {
          Text: {
            Charset: "UTF-8",
            Data:
              "Use this link to reset your Hollis password:\n\n" +
              `${resetUrl}\n\n` +
              `This link expires at ${params.expiresAt.toISOString()}.`,
          },
        },
      },
    },
  }));
}
