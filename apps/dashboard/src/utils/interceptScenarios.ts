/**
 * NOSIH Protocol — Intercept Scenario Generator.
 *
 * Provides a large library of realistic intercept templates across
 * all four NOSIH tiers (T0–T3), multiple agent identities, and diverse
 * operational categories. Batch generation uses full randomisation to
 * ensure every run produces a varied, legit-looking output stream.
 */

import type { InterceptRequest } from "../api/types.js";

// ── UUID v7 Generator ────────────────────────────────────────────────────────

/**
 * Generate a valid UUID v7 compliant with NOSIH regex:
 * /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
 */
export function generateUuidV7(): string {
  const now = Date.now();
  const timeHex = now.toString(16).padStart(12, "0");
  const p1 = timeHex.slice(0, 8);
  const p2 = timeHex.slice(8, 12);
  const rand12 = Math.floor(Math.random() * 0xfff).toString(16).padStart(3, "0");
  const p3 = `7${rand12}`;
  const variantChar = ["8", "9", "a", "b"][Math.floor(Math.random() * 4)]!;
  const rand12b = Math.floor(Math.random() * 0xfff).toString(16).padStart(3, "0");
  const p4 = `${variantChar}${rand12b}`;
  let p5 = "";
  for (let i = 0; i < 3; i++) {
    p5 += Math.floor(Math.random() * 0xffff).toString(16).padStart(4, "0");
  }
  return `${p1}-${p2}-${p3}-${p4}-${p5}`.toLowerCase();
}

function utcTimestamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, ".000000Z");
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]!;
}

function randInt(min: number, max: number): number {
  return Math.floor(min + Math.random() * (max - min + 1));
}

function randFloat(min: number, max: number, decimals = 3): number {
  return parseFloat((min + Math.random() * (max - min)).toFixed(decimals));
}

function randHex(bytes: number): string {
  return Array.from({ length: bytes }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, "0"),
  ).join("");
}

function randSha256(): string {
  return randHex(32);
}

// ── Agent Pool (16 unique Ed25519 public keys — all exactly 64 hex chars) ────

export const KNOWN_AGENTS: { id: string; name: string; role: string }[] = [
  { id: "4f1c9a7e6b3d2f8a5c0e1d9b7a6f4c2e8d1a3b5f7c9e0d2a4b6c8e1f3a5d7b9c", name: "rover-alpha",      role: "Robotics Controller" },
  { id: "d8a5c0e1d9b7a6f4c2e8d1a3b5f7c9e0d2a4b6c8e1f3a5d7b9c4f1c9a7e6b3d2", name: "mcp-orchestrator", role: "MCP Orchestration Engine" },
  { id: "1a3b5f7c9e0d2a4b6c8e1f3a5d7b9c4f1c9a7e6b3d2f8a5c0e1d9b7a6f4c2e8d", name: "plc-controller-7", role: "Industrial PLC" },
  { id: "a2c4e6f8b0d2e4f6a8c0e2f4b6d8f0a2c4e6f8b0d2e4f6a8c0e2f4b6d8f0a2c4", name: "finance-bot-3",    role: "Treasury Automation Agent" },
  { id: "7e9f1b3d5a7c9e1f3b5d7a9c1e3f5b7d9a1c3e5f7b9d1a3c5e7f9b1d3a5c7e9f", name: "arm-bot-12",       role: "Robotic Arm Controller" },
  { id: "3c5a7b9d1f3e5c7a9b1d3f5e7c9a1b3d5f7e9c1a3b5d7f9e1c3a5b7d9f1e3c5a", name: "sensor-hub-east",  role: "Sensor Aggregation Node" },
  { id: "f1d3b5a7c9e1f3d5b7a9c1e3f5d7b9a1c3e5f7d9b1a3c5e7f9d1b3a5c7e9f1d3", name: "audit-daemon",     role: "Compliance and Audit Agent" },
  { id: "b9d1f3e5a7c9b1d3f5e7a9c1b3d5f7e9a1c3b5d7f9e1a3b5c7d9f1e3b5a7c9d1", name: "nav-planner-2",    role: "Autonomous Navigation Planner" },
  { id: "5e7c9a1b3d5f7e9c1a3b5d7f9e1c3a5b7d9f1e3c5a7b9d1f3e5c7a9b1d3f5e7c", name: "fs-watchdog",      role: "Filesystem Security Monitor" },
  { id: "2a4c6e8f0b2d4f6a8c0e2f4b6d8f0a2c4e6f8b0d2e4f6a8c0e2f4b6d8f0a2c4e", name: "exec-engine-5",    role: "Remote Execution Engine" },
  { id: "8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a", name: "gripper-delta",    role: "End-Effector Controller" },
  { id: "c6e8f0a2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8", name: "economy-node-1",   role: "Decentralised Economy Node" },
  { id: "4b6d8e0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b", name: "vision-proc-3",    role: "Computer Vision Processor" },
  { id: "0e2f4a6c8b0d2e4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f", name: "reactor-monitor",   role: "Nuclear Safety Monitor" },
  { id: "9d1e3c5a7b9d1e3c5a7b9d1e3c5a7b9d1e3c5a7b9d1e3c5a7b9d1e3c5a7b9d1e", name: "supply-chain-ai",   role: "Supply Chain Optimizer" },
  { id: "6c8e0a2b4d6c8e0a2b4d6c8e0a2b4d6c8e0a2b4d6c8e0a2b4d6c8e0a2b4d6c8e", name: "telemetry-agg",    role: "Fleet Telemetry Aggregator" },
];

// ── Scenario Category and Tier Types ─────────────────────────────────────────

export interface ScenarioTemplate {
  category: "Robotics" | "MCP Tool" | "Industrial" | "Filesystem" | "Financial" | "Network" | "Healthcare";
  tierHint: "T0_OBSERVE" | "T1_PREPARE" | "T2_ACT" | "T3_COMMIT";
  resource: string;
  action: string;
  paramsGenerator: () => Record<string, unknown>;
}

// ── Scenario Template Library ─────────────────────────────────────────────────
// All resources use schemes the gateway's DEFAULT_TIER_RULES recognises so
// that the policy engine assigns genuine T0/T1/T2/T3 tiers rather than
// defaulting every unknown resource to DENY.

export const SCENARIO_TEMPLATES: ScenarioTemplate[] = [

  // ── T0 OBSERVE — auto-approved, read-only ─────────────────────────────────

  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "ros2:///camera/front",
    action: "subscribe",
    paramsGenerator: () => ({
      fps: pick([15, 24, 30, 60]),
      format: pick(["rgb8", "bgr8", "mono16", "compressed"]),
      quality: pick(["low", "medium", "high", "ultra"]),
      bufferFrames: randInt(1, 8),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "ros2:///camera/rear",
    action: "subscribe",
    paramsGenerator: () => ({
      fps: pick([10, 15, 30]),
      format: pick(["rgb8", "mono8", "depth16"]),
      roi: { x: randInt(0, 100), y: randInt(0, 100), width: 640, height: 480 },
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "ros2:///sensor/imu",
    action: "subscribe",
    paramsGenerator: () => ({
      topic: "/imu/data",
      rateHz: pick([50, 100, 200, 500]),
      frameId: pick(["base_link", "imu_link", "odom"]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "ros2:///battery/state",
    action: "subscribe",
    paramsGenerator: () => ({
      topic: "/battery_state",
      warnThresholdPct: randInt(15, 30),
      criticalThresholdPct: randInt(5, 14),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "ros2:///enc_wheels",
    action: "subscribe",
    paramsGenerator: () => ({
      ticksPerRevolution: pick([512, 1024, 2048, 4096]),
      wheelDiameterM: randFloat(0.1, 0.3, 3),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "ros2:///diagnostics",
    action: "subscribe",
    paramsGenerator: () => ({
      aggregatorName: pick(["diagnostic_aggregator", "robot_monitor"]),
      updateRateHz: pick([1, 5, 10]),
    }),
  },
  {
    category: "MCP Tool",
    tierHint: "T0_OBSERVE",
    resource: "mcp://database/query",
    action: "call",
    paramsGenerator: () => ({
      table: pick(["telemetry_logs", "agent_events", "audit_records", "sensor_readings"]),
      limit: pick([10, 25, 50, 100]),
      orderBy: pick(["timestamp DESC", "agent_id ASC", "risk_score DESC"]),
      filter: { since: new Date(Date.now() - randInt(1, 72) * 3600000).toISOString() },
    }),
  },
  {
    category: "MCP Tool",
    tierHint: "T0_OBSERVE",
    resource: "mcp://filesystem/readFile",
    action: "call",
    paramsGenerator: () => ({
      path: pick([
        `/var/log/nosih/agent_${randInt(1, 20)}.log`,
        `/opt/nosih/config/policy.json`,
        `/proc/device-tree/model`,
        `/etc/nosih/gateway.conf`,
      ]),
      encoding: pick(["utf-8", "base64"]),
    }),
  },
  {
    category: "MCP Tool",
    tierHint: "T0_OBSERVE",
    resource: "mcp://filesystem/readDirectory",
    action: "call",
    paramsGenerator: () => ({
      path: pick(["/var/log/nosih", "/opt/nosih/agents", "/tmp/staging"]),
      recursive: pick([true, false]),
      maxEntries: pick([50, 100, 250]),
    }),
  },
  {
    category: "Network",
    tierHint: "T0_OBSERVE",
    resource: "mqtt://fleet/+/telemetry/sensor",
    action: "subscribe",
    paramsGenerator: () => ({
      agentId: `agent-${randInt(100, 999)}`,
      topic: `fleet/unit-${randInt(1, 20)}/telemetry/sensor`,
      qos: pick([0, 1]),
    }),
  },
  {
    category: "Network",
    tierHint: "T0_OBSERVE",
    resource: "mqtt://plant/+/status",
    action: "subscribe",
    paramsGenerator: () => ({
      plant: pick(["alpha", "beta", "gamma", "delta"]),
      zone: `zone-${randInt(1, 12)}`,
      retain: pick([true, false]),
    }),
  },
  {
    category: "Industrial",
    tierHint: "T0_OBSERVE",
    resource: "opcua://plc-main",
    action: "read",
    paramsGenerator: () => ({
      nodeId: `ns=2;s=Line${randInt(1, 8)}/Sensor/Temp`,
      samplingIntervalMs: pick([100, 500, 1000, 5000]),
      deadband: randFloat(0.01, 0.5, 3),
    }),
  },
  {
    category: "Industrial",
    tierHint: "T0_OBSERVE",
    resource: "opcua://scada-east",
    action: "observe",
    paramsGenerator: () => ({
      nodeId: `ns=3;s=Reactor${randInt(1, 4)}/Pressure`,
      publishingIntervalMs: pick([200, 500, 1000]),
      queueSize: pick([5, 10, 20]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "engine://system1/perception",
    action: "inference",
    paramsGenerator: () => ({
      modelId: pick(["yolov8-seg", "depth-anything", "clip-vit-l"]),
      inputResolution: pick(["640x480", "1280x720", "1920x1080"]),
      confidenceThreshold: randFloat(0.3, 0.9, 2),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "engine://hal/lidar",
    action: "monitor",
    paramsGenerator: () => ({
      device: pick(["/dev/lidar0", "/dev/lidar1"]),
      scanRateHz: pick([10, 20, 40]),
      rangeMaxM: randFloat(10, 50, 1),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "nosih://interface/status",
    action: "call",
    paramsGenerator: () => ({
      includeMetrics: pick([true, false]),
      format: pick(["json", "compact"]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "nosih://interface/memory/recall",
    action: "call",
    paramsGenerator: () => ({
      query: pick(["last mission context", "operator preferences", "known obstacles", "calibration state"]),
      maxResults: pick([3, 5, 10]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T0_OBSERVE",
    resource: "a2a://report-agent.nosih.local/status",
    action: "a2a.send",
    paramsGenerator: () => ({
      requestType: "status_check",
      agentId: `agent-${randInt(100, 999)}`,
      includeSubsystems: pick([true, false]),
    }),
  },

  // ── T1 PREPARE — auto-approved, low-impact writes ─────────────────────────

  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "ros2:///plan",
    action: "publish",
    paramsGenerator: () => ({
      plannerType: pick(["navfn", "smac_planner", "teb_local_planner"]),
      goalPose: {
        x: randFloat(-20, 20),
        y: randFloat(-20, 20),
        theta: randFloat(-3.14, 3.14),
      },
      toleranceM: randFloat(0.05, 0.3, 2),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "ros2:///waypoints",
    action: "publish",
    paramsGenerator: () => ({
      waypoints: Array.from({ length: randInt(2, 6) }, () => ({
        x: randFloat(-15, 15),
        y: randFloat(-15, 15),
      })),
      loopPath: pick([true, false]),
      maxSpeedMps: randFloat(0.2, 1.2, 2),
    }),
  },
  {
    category: "MCP Tool",
    tierHint: "T1_PREPARE",
    resource: "mcp://filesystem/writeFile",
    action: "call",
    paramsGenerator: () => ({
      path: `/tmp/nosih_staging/${generateUuidV7()}.json`,
      mode: "0644",
      createDirs: true,
      estimatedBytes: randInt(512, 65536),
    }),
  },
  {
    category: "MCP Tool",
    tierHint: "T1_PREPARE",
    resource: "mcp://filesystem/getFileInfo",
    action: "call",
    paramsGenerator: () => ({
      path: pick([
        `/opt/nosih/policies/current.json`,
        `/var/run/agent/lock_${randInt(1, 10)}`,
        `/etc/nosih/agents/${randInt(100, 999)}.conf`,
      ]),
      followSymlinks: pick([true, false]),
    }),
  },
  {
    category: "Network",
    tierHint: "T1_PREPARE",
    resource: "mqtt://fleet/commands/stage",
    action: "publish",
    paramsGenerator: () => ({
      targetUnit: `unit-${randInt(1, 20)}`,
      command: pick(["prepare_mission", "pre_flight_check", "load_manifest", "stage_payload"]),
      priority: pick(["low", "normal", "high"]),
      ttlSeconds: pick([30, 60, 300]),
    }),
  },
  {
    category: "Network",
    tierHint: "T1_PREPARE",
    resource: "mqtt://factory/conveyor/stage",
    action: "publish",
    paramsGenerator: () => ({
      lineId: `LINE-${String(randInt(1, 8)).padStart(2, "0")}`,
      operation: pick(["set_speed_target", "queue_batch", "reserve_slot"]),
      targetSpeedMps: randFloat(0.1, 2.5, 2),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "engine://system2/plan",
    action: "create",
    paramsGenerator: () => ({
      taskType: pick(["pick_and_place", "inspection_route", "delivery_mission", "patrol_circuit"]),
      constraints: {
        maxDurationMin: randInt(5, 60),
        forbiddenZones: randInt(0, 3),
        safetyMarginM: randFloat(0.2, 1.0, 2),
      },
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "engine://system2/plan",
    action: "validate",
    paramsGenerator: () => ({
      planId: generateUuidV7(),
      validationLevel: pick(["basic", "full", "simulation"]),
      timeoutSec: randInt(5, 30),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "engine://capsule/nav-stack",
    action: "load",
    paramsGenerator: () => ({
      capsuleId: `nav-${pick(["v2.1", "v2.2", "v3.0-beta"])}`,
      sha256: randSha256(),
      autoActivate: pick([true, false]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "nosih://interface/speak",
    action: "call",
    paramsGenerator: () => ({
      text: pick([
        "Preparing for next task. Estimated duration: " + randInt(1, 15) + " minutes.",
        "Battery at " + randInt(20, 90) + "%. Recommending charging station alpha.",
        "Obstacle detected in zone " + randInt(1, 8) + ". Replanning route.",
        "Mission waypoints loaded. Awaiting operator confirmation.",
      ]),
      voice: pick(["en-US-Wavenet-C", "en-GB-Wavenet-A", "en-AU-Wavenet-B"]),
      priority: pick(["normal", "high"]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "nosih://interface/hud/mission-status",
    action: "call",
    paramsGenerator: () => ({
      panel: pick(["mission-status", "agent-health", "risk-overview", "fleet-map"]),
      data: { progress: randInt(0, 100), status: pick(["planning", "staging", "ready"]) },
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "nosih://interface/memory/store",
    action: "call",
    paramsGenerator: () => ({
      key: pick(["last_known_pose", "operator_preference", "hazard_zones", "calibration_offset"]),
      value: { timestamp: utcTimestamp(), data: randHex(8) },
      ttlSeconds: pick([300, 3600, 86400]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "open-rmf://tasks/dispatch",
    action: "prepare",
    paramsGenerator: () => ({
      taskType: pick(["delivery", "cleaning", "patrol", "inspection"]),
      robotId: `AMR-${String(randInt(1, 12)).padStart(2, "0")}`,
      priority: randInt(1, 10),
      estimatedDurationMin: randInt(3, 45),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T1_PREPARE",
    resource: "a2a://planner-agent.nosih.local/inspect",
    action: "a2a.send",
    paramsGenerator: () => ({
      target: pick(["mission_queue", "agent_registry", "policy_cache"]),
      depth: pick(["summary", "detailed", "full"]),
    }),
  },

  // ── T2 ACT — human-review, physical state changes ─────────────────────────

  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "ros2:///cmd_vel",
    action: "publish",
    paramsGenerator: () => ({
      twist: {
        linear: { x: randFloat(-0.5, 0.5), y: 0, z: 0 },
        angular: { x: 0, y: 0, z: randFloat(-0.4, 0.4) },
      },
      durationMs: randInt(200, 3000),
      collisionCheck: pick([true, true, false]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "ros2:///cmd_wheels",
    action: "publish",
    paramsGenerator: () => ({
      leftRpm: randFloat(-120, 120, 1),
      rightRpm: randFloat(-120, 120, 1),
      durationMs: randInt(100, 2000),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "ros2:///joint_commands",
    action: "publish",
    paramsGenerator: () => ({
      joints: ["shoulder_pan", "shoulder_lift", "elbow"].map((j) => ({
        name: j,
        position: randFloat(-3.14, 3.14),
        velocity: randFloat(0.0, 1.0, 2),
      })),
      interpolateMs: randInt(500, 3000),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "ros2:///gripper/command",
    action: "publish",
    paramsGenerator: () => ({
      position: randFloat(0, 1, 2),
      maxEffort: randFloat(5, 80, 1),
      mode: pick(["position", "force", "adaptive"]),
    }),
  },
  {
    category: "Industrial",
    tierHint: "T2_ACT",
    resource: "opcua://plc-main",
    action: "write",
    paramsGenerator: () => ({
      nodeId: `ns=2;s=Line${randInt(1, 8)}/Actuator/Valve${randInt(1, 12)}`,
      value: randFloat(0, 100, 1),
      dataType: pick(["Float", "Int32", "Boolean"]),
      verifyWrite: pick([true, true, false]),
    }),
  },
  {
    category: "Industrial",
    tierHint: "T2_ACT",
    resource: "opcua://motor-drive-cluster",
    action: "write",
    paramsGenerator: () => ({
      nodeId: `ns=4;s=Drive${randInt(1, 6)}/SpeedSetpoint`,
      targetRpm: randInt(200, 3000),
      rampTimeSec: randInt(2, 30),
    }),
  },
  {
    category: "Network",
    tierHint: "T2_ACT",
    resource: "mqtt://factory/cmd/valve-bank",
    action: "publish",
    paramsGenerator: () => ({
      valveId: `VLV-${String(randInt(1, 24)).padStart(2, "0")}`,
      command: pick(["open", "close", "partial"]),
      percentOpen: randInt(0, 100),
      rampSec: randInt(2, 15),
    }),
  },
  {
    category: "Network",
    tierHint: "T2_ACT",
    resource: "mqtt://fleet/cmd/actuate",
    action: "publish",
    paramsGenerator: () => ({
      unitId: `unit-${randInt(1, 20)}`,
      actuatorId: pick(["lift", "tilt", "extend", "retract"]),
      targetPositionMm: randInt(0, 1000),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "mavlink://drone-01/cmd_vel",
    action: "publish",
    paramsGenerator: () => ({
      vx: randFloat(-5, 5, 2),
      vy: randFloat(-5, 5, 2),
      vz: randFloat(-2, 2, 2),
      yawRate: randFloat(-0.5, 0.5, 3),
      frameId: pick(["BODY_NED", "LOCAL_NED"]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: `mavlink://drone-0${randInt(1, 5)}/cmd/takeoff`,
    action: "call",
    paramsGenerator: () => ({
      altitudeM: randFloat(2, 50, 1),
      holdSeconds: randInt(3, 30),
      abortOnWindMs: pick([8, 10, 15]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "mavlink://drone-01/cmd/land",
    action: "call",
    paramsGenerator: () => ({
      targetLat: randFloat(12.9, 13.1, 6),
      targetLon: randFloat(77.5, 77.7, 6),
      descentRateMps: randFloat(0.3, 1.5, 2),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "engine://system2/execute",
    action: "execute",
    paramsGenerator: () => ({
      planId: generateUuidV7(),
      executionMode: pick(["sequential", "parallel", "adaptive"]),
      safetyWatchdogMs: randInt(500, 5000),
      rollbackOnFailure: pick([true, true, false]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "nosih://interface/notify",
    action: "call",
    paramsGenerator: () => ({
      channel: pick(["operator-console", "mobile-app", "control-room", "on-call-pager"]),
      severity: pick(["info", "warning", "critical"]),
      message: pick([
        `Anomaly detected on zone ${randInt(1, 12)} — agent requesting guidance`,
        `Mission objective ${randInt(1, 8)} completed. Awaiting next directive.`,
        `Risk score elevated to ${randFloat(0.6, 0.9, 2)} — operator review advised`,
      ]),
      requireAck: pick([true, false]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "nosih://interface/mode",
    action: "call",
    paramsGenerator: () => ({
      newMode: pick(["autonomous", "supervised", "manual", "standby", "emergency"]),
      reason: pick(["mission_start", "operator_request", "safety_trigger", "scheduled_maintenance"]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "open-rmf://fleet/command",
    action: "call",
    paramsGenerator: () => ({
      robotId: `AMR-${String(randInt(1, 12)).padStart(2, "0")}`,
      command: pick(["go_to", "dock", "undock", "cancel_task"]),
      destination: pick(["charging-bay-1", "pickup-station-A", "dropoff-zone-3", "maintenance-bay"]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "a2a://nav-agent.nosih.local/navigate",
    action: "a2a.send",
    paramsGenerator: () => ({
      destination: { x: randFloat(-30, 30), y: randFloat(-30, 30) },
      avoidanceMode: pick(["static", "dynamic", "aggressive"]),
      maxSpeedMps: randFloat(0.3, 1.5, 2),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T2_ACT",
    resource: "a2a://gripper-agent.nosih.local/gripper",
    action: "a2a.send",
    paramsGenerator: () => ({
      action: pick(["grasp", "release", "probe_force"]),
      objectClass: pick(["box-small", "cylinder-medium", "fragile-glass", "tool-handle"]),
      forceLimit: randFloat(5, 60, 1),
    }),
  },

  // ── T3 COMMIT — must have human approval, irreversible ────────────────────

  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "ros2:///mode_change",
    action: "publish",
    paramsGenerator: () => ({
      newMode: pick(["EMERGENCY_STOP", "MAINTENANCE", "FACTORY_RESET", "SAFE_SHUTDOWN"]),
      reason: pick(["operator_command", "fault_detected", "scheduled", "safety_trigger"]),
      confirmationCode: randHex(4).toUpperCase(),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "humanoid://unit-7/workspace/novel/enter",
    action: "call",
    paramsGenerator: () => ({
      zoneId: `ZONE-${String(randInt(1, 20)).padStart(2, "0")}`,
      riskAssessmentId: generateUuidV7(),
      operatorAuthorization: `AUTH-${randHex(4).toUpperCase()}`,
      estimatedDurationMin: randInt(2, 60),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "humanoid://unit-3/safety/envelope",
    action: "override",
    paramsGenerator: () => ({
      envelopeType: pick(["velocity_limit", "torque_limit", "workspace_boundary", "collision_threshold"]),
      newValue: randFloat(0.1, 2.0, 3),
      justification: pick(["calibration", "maintenance_mode", "emergency_bypass", "test_procedure"]),
      supervisorId: `SUP-${randInt(1000, 9999)}`,
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "humanoid://unit-5/estop",
    action: "override",
    paramsGenerator: () => ({
      overrideType: pick(["soft_reset", "hard_reset", "fault_clear"]),
      safetyChecksPassed: true,
      authorizedBy: `OPS-${randHex(4).toUpperCase()}`,
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "mavlink://drone-01/cmd/arm",
    action: "call",
    paramsGenerator: () => ({
      force: pick([true, false]),
      preArmChecksOverride: false,
      operatorId: `PLT-${randInt(100, 999)}`,
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "mavlink://drone-02/cmd/mission",
    action: "call",
    paramsGenerator: () => ({
      missionId: generateUuidV7(),
      waypointCount: randInt(3, 20),
      bvlosApproval: `BVLOS-${randHex(4).toUpperCase()}`,
      geofenceId: `GF-${randInt(1, 50)}`,
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "mavlink://drone-03/cmd/mode",
    action: "call",
    paramsGenerator: () => ({
      targetMode: pick(["OFFBOARD", "ACRO", "STABILIZE", "POSCTL"]),
      reason: pick(["operator_override", "emergency_recovery", "test_flight"]),
      confirmCode: randHex(6),
    }),
  },
  {
    category: "Industrial",
    tierHint: "T3_COMMIT",
    resource: "opcua://plc-main/safety/emergency-stop",
    action: "call",
    paramsGenerator: () => ({
      zone: pick(["ZONE_A", "ZONE_B", "ZONE_C", "ALL"]),
      estopType: pick(["Category_0", "Category_1", "Category_2"]),
      interlockOverride: false,
      authorisationToken: randHex(16),
    }),
  },
  {
    category: "Industrial",
    tierHint: "T3_COMMIT",
    resource: "opcua://scada-east/emergency/purge",
    action: "call",
    paramsGenerator: () => ({
      chamberIds: pick([["ALPHA"], ["ALPHA", "BETA"], ["ALPHA", "BETA", "GAMMA"]]),
      purgeAgent: pick(["N2", "CO2", "Ar"]),
      protocolRef: pick(["SEC-9021", "SEC-9022", "EMERG-001"]),
      operatorCode: `OPS-${randHex(4).toUpperCase()}`,
    }),
  },
  {
    category: "MCP Tool",
    tierHint: "T3_COMMIT",
    resource: "mcp://exec/flash-firmware",
    action: "exec.run",
    paramsGenerator: () => ({
      device: pick(["/dev/ttyUSB0", "/dev/mmcblk0", "/dev/nvme0n1"]),
      firmwareSha256: randSha256(),
      requireSignatureVerification: true,
      rollbackEnabled: pick([true, false]),
    }),
  },
  {
    category: "MCP Tool",
    tierHint: "T3_COMMIT",
    resource: "mcp://exec/deploy-container",
    action: "call",
    paramsGenerator: () => ({
      image: pick([
        `nosih/agent-controller:${randInt(1, 5)}.${randInt(0, 9)}.${randInt(0, 9)}`,
        `nosih/policy-gateway:${randInt(1, 3)}.${randInt(0, 5)}.0`,
        `nosih/telemetry-sink:stable`,
      ]),
      imageSha256: randSha256(),
      namespace: pick(["nosih-prod", "nosih-staging", "nosih-edge"]),
      replicas: randInt(1, 6),
      networkPolicy: pick(["restricted", "internal-only", "full-mesh"]),
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "a2a://config-agent.nosih.local/configure",
    action: "a2a.send",
    paramsGenerator: () => ({
      component: pick(["policy-engine", "risk-scorer", "approval-queue", "ledger"]),
      configDiff: { updated: randInt(1, 8), keys: [`param_${randHex(4)}`] },
      requiresRestart: pick([true, false]),
      changeTicket: `CHG-${randInt(10000, 99999)}`,
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "a2a://provision-agent.nosih.local/provision",
    action: "a2a.send",
    paramsGenerator: () => ({
      targetAgentId: pick(KNOWN_AGENTS).id,
      capabilityTokenType: pick(["T2_ACT_LIMITED", "T3_SUPERVISOR", "FULL_AUTONOMY"]),
      validForHours: pick([1, 6, 24, 168]),
      issuingAuthority: `NOSIH-CA-${randHex(4).toUpperCase()}`,
    }),
  },
  {
    category: "Robotics",
    tierHint: "T3_COMMIT",
    resource: "open-rmf://fleet/override",
    action: "override",
    paramsGenerator: () => ({
      robotId: `AMR-${String(randInt(1, 12)).padStart(2, "0")}`,
      overrideType: pick(["force_dock", "emergency_stop", "manual_takeover"]),
      reason: pick(["safety_violation", "operator_intervention", "fleet_conflict"]),
      supervisorCode: `SUP-${randHex(4).toUpperCase()}`,
    }),
  },
  {
    category: "Network",
    tierHint: "T3_COMMIT",
    resource: "mqtt://factory/emergency/shutdown",
    action: "publish",
    paramsGenerator: () => ({
      targetLines: pick([["LINE-01"], ["LINE-01", "LINE-02"], ["ALL"]]),
      shutdownType: pick(["graceful", "immediate", "emergency"]),
      authorisationCode: randHex(16),
    }),
  },
  {
    category: "Network",
    tierHint: "T3_COMMIT",
    resource: "mqtt://fleet/firmware/ota",
    action: "publish",
    paramsGenerator: () => ({
      targets: pick([["unit-01"], ["unit-01", "unit-02", "unit-03"], ["ALL"]]),
      firmwareVersion: `${randInt(1, 5)}.${randInt(0, 9)}.${randInt(0, 9)}`,
      sha256: randSha256(),
      rolloutStrategy: pick(["canary", "blue-green", "rolling", "all-at-once"]),
    }),
  },
];

// ── Scenario Generators ───────────────────────────────────────────────────────

export function generateRandomInterceptRequest(index?: number): InterceptRequest {
  const template =
    typeof index === "number" && index >= 0 && index < SCENARIO_TEMPLATES.length
      ? SCENARIO_TEMPLATES[index]!
      : pick(SCENARIO_TEMPLATES);

  const agent = pick(KNOWN_AGENTS);
  const reqId = generateUuidV7();
  const tokId = generateUuidV7();

  return {
    requestId: reqId,
    timestamp: utcTimestamp(),
    agentId: agent.id,
    tokenId: tokId,
    resource: template.resource,
    action: template.action,
    params: template.paramsGenerator(),
  };
}

export function generateBatchInterceptRequests(count: number): InterceptRequest[] {
  const t0 = SCENARIO_TEMPLATES.filter((t) => t.tierHint === "T0_OBSERVE");
  const t1 = SCENARIO_TEMPLATES.filter((t) => t.tierHint === "T1_PREPARE");
  const t2 = SCENARIO_TEMPLATES.filter((t) => t.tierHint === "T2_ACT");
  const t3 = SCENARIO_TEMPLATES.filter((t) => t.tierHint === "T3_COMMIT");

  const results: InterceptRequest[] = [];

  for (let i = 0; i < count; i++) {
    // Balanced tier roll: 30% T0, 30% T1, 25% T2, 15% T3
    const roll = Math.random();
    let pool: ScenarioTemplate[];
    if (roll < 0.30 && t0.length > 0) {
      pool = t0;
    } else if (roll < 0.60 && t1.length > 0) {
      pool = t1;
    } else if (roll < 0.85 && t2.length > 0) {
      pool = t2;
    } else if (t3.length > 0) {
      pool = t3;
    } else {
      pool = SCENARIO_TEMPLATES;
    }

    const template = pick(pool);
    const agent = pick(KNOWN_AGENTS);

    results.push({
      requestId: generateUuidV7(),
      timestamp: utcTimestamp(),
      agentId: agent.id,
      tokenId: generateUuidV7(),
      resource: template.resource,
      action: template.action,
      params: template.paramsGenerator(),
    });
  }

  return results;
}



