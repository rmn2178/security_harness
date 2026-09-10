FROM node:22-bookworm-slim

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

WORKDIR /app

# Glama and some minimal container environments don't ship `corepack` by default.
# Install pnpm explicitly so `pnpm install --frozen-lockfile` is reliable everywhere.
RUN npm i -g pnpm@9.15.0

# Copy the minimal workspace surface needed to build and run nosih-mcp.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY apps/nosih-mcp ./apps/nosih-mcp
COPY packages ./packages

RUN pnpm install --frozen-lockfile && pnpm --filter nosih-mcp build

USER node

CMD ["node", "apps/nosih-mcp/dist/index.cjs", "--stdio"]
