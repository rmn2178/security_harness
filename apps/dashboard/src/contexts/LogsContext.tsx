/**
 * LogsContext - manages execution logs from Intercept tests and provides
 * log export capabilities for the top-right header and terminal.
 */

import { createContext, useContext, useState, useCallback, type ReactNode } from "react";
import type { InterceptRequest } from "../api/types.js";

export interface InterceptLogItem {
  id: string;
  timestamp: string;
  durationMs: number;
  request: InterceptRequest;
  response: unknown;
  status: "allow" | "deny" | "escalate" | "error";
  error?: string;
  tier?: string;
}

interface LogsContextValue {
  logs: InterceptLogItem[];
  addLog: (log: InterceptLogItem) => void;
  addLogs: (newLogs: InterceptLogItem[]) => void;
  clearLogs: () => void;
  downloadLogsJson: () => void;
  downloadLogsText: () => void;
}

const LogsContext = createContext<LogsContextValue | null>(null);

export function LogsProvider({ children }: { children: ReactNode }) {
  const [logs, setLogs] = useState<InterceptLogItem[]>([]);

  const addLog = useCallback((log: InterceptLogItem) => {
    setLogs((prev) => [log, ...prev].slice(0, 500));
  }, []);

  const addLogs = useCallback((newLogs: InterceptLogItem[]) => {
    setLogs((prev) => [...newLogs, ...prev].slice(0, 500));
  }, []);

  const clearLogs = useCallback(() => {
    setLogs([]);
  }, []);

  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const downloadLogsJson = useCallback(() => {
    if (logs.length === 0) return;
    const exportData = {
      exportedAt: new Date().toISOString(),
      totalLogs: logs.length,
      logs,
    };
    downloadFile(
      JSON.stringify(exportData, null, 2),
      `nosih-intercept-logs-${Date.now()}.json`,
      "application/json",
    );
  }, [logs]);

  const downloadLogsText = useCallback(() => {
    if (logs.length === 0) return;
    const lines = [
      `================================================================================`,
      `NOSIH PROTOCOL - INTERCEPT EXECUTION LOGS`,
      `Exported: ${new Date().toISOString()}`,
      `Total Intercept Entries: ${logs.length}`,
      `================================================================================`,
      "",
    ];

    logs.forEach((item, idx) => {
      lines.push(
        `[#${logs.length - idx}] [${item.timestamp}] STATUS: ${item.status.toUpperCase()} (${item.durationMs}ms)`,
      );
      lines.push(`  Request ID : ${item.request.requestId}`);
      lines.push(`  Resource   : ${item.request.resource}`);
      lines.push(`  Action     : ${item.request.action}`);
      lines.push(`  Agent ID   : ${item.request.agentId}`);
      if (item.tier) {
        lines.push(`  Tier       : ${item.tier}`);
      }
      if (item.error) {
        lines.push(`  Error      : ${item.error}`);
      }
      lines.push(`  --- Request Payload ---`);
      lines.push(`  ${JSON.stringify(item.request, null, 2).replace(/\n/g, "\n  ")}`);
      lines.push(`  --- Policy Decision Response ---`);
      lines.push(`  ${JSON.stringify(item.response, null, 2).replace(/\n/g, "\n  ")}`);
      lines.push(`--------------------------------------------------------------------------------`);
    });

    downloadFile(lines.join("\n"), `nosih-intercept-logs-${Date.now()}.log`, "text/plain");
  }, [logs]);

  return (
    <LogsContext.Provider
      value={{
        logs,
        addLog,
        addLogs,
        clearLogs,
        downloadLogsJson,
        downloadLogsText,
      }}
    >
      {children}
    </LogsContext.Provider>
  );
}

const defaultLogsValue: LogsContextValue = {
  logs: [],
  addLog: () => {},
  addLogs: () => {},
  clearLogs: () => {},
  downloadLogsJson: () => {},
  downloadLogsText: () => {},
};

export function useLogs(): LogsContextValue {
  const ctx = useContext(LogsContext);
  return ctx ?? defaultLogsValue;
}

