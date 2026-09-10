/**
 * @nosih/os-core — NOSIH OS Main Entrypoint.
 *
 * NOSIH OS = OpenClaw (agent runtime) + NOSIH Protocol (governance) + Avatar (face) + Multimodal (Jarvis bridge)
 *
 * This package provides:
 * 1. NosihOS class — unified boot/shutdown lifecycle
 * 2. OpenClaw adapter — governance middleware for all OpenClaw operations
 * 3. Avatar bridge — connects 3D face + Conversation Compiler + Widget HUD
 * 4. Multimodal bridge — voice (Qwen3.5-Omni / ElevenLabs), gesture, holographic HUD
 * 5. Evidence HUD — real-time ledger viewer
 *
 * @module @nosih/os-core
 */

export { NosihOS } from "./nosih-os.js";
export { AvatarBridge } from "./avatar-bridge.js";
export { EvidenceHUD } from "./evidence-hud.js";
export type { NosihOSConfig, NosihOSStatus, AvatarConfig, EvidenceHUDConfig } from "./types.js";

// Re-export OpenClaw adapter
export {
  OpenClawAdapter,
  SystemStateTracker,
  DEFAULT_PHYSICAL_POLICIES,
} from "@pshkv/openclaw-adapter";
export type {
  OpenClawToolCall,
  OpenClawMCPCall,
  OpenClawNodeAction,
  NosihTier,
  GovernanceResult,
  OpenClawAdapterConfig,
  CrossSystemPolicy,
} from "@pshkv/openclaw-adapter";
