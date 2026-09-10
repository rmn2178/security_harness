/**
 * NOSIH Persistence — In-Memory Token Store.
 *
 * @module @nosih/persistence/in-memory-token-store
 */

import type { NosihCapabilityToken, UUIDv7 } from "@pshkv/core";
import type { TokenStore } from "./interfaces.js";

export class InMemoryTokenStore implements TokenStore {
  private tokens = new Map<string, NosihCapabilityToken>();

  async store(token: NosihCapabilityToken): Promise<void> {
    this.tokens.set(token.tokenId, token);
  }

  async get(tokenId: UUIDv7): Promise<NosihCapabilityToken | undefined> {
    return this.tokens.get(tokenId);
  }

  async getBySubject(subject: string): Promise<readonly NosihCapabilityToken[]> {
    return Array.from(this.tokens.values()).filter(
      (t) => t.subject === subject,
    );
  }

  async remove(tokenId: UUIDv7): Promise<boolean> {
    return this.tokens.delete(tokenId);
  }

  async count(): Promise<number> {
    return this.tokens.size;
  }
}
