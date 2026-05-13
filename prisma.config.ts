import path from "node:path";
import { defineConfig, env } from "prisma/config";

import "dotenv/config";

export default defineConfig({
  earlyAccess: true,
  schema: path.join(import.meta.dirname, "prisma", "schema.prisma"),
  datasource: {
    url: env("DATABASE_URL"),
  },
});
