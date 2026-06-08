import type {
  AssistantMessage,
  Message,
  Tool,
  ToolResultMessage,
  UserMessage,
} from "@earendil-works/pi-ai";
import { Type } from "@earendil-works/pi-ai";
import { describe, expect, it } from "vitest";
import {
  buildHistory,
  convertImagesToKiro,
  convertToolsToKiro,
  getContentText,
  normalizeMessages,
  TOOL_RESULT_LIMIT,
  truncate,
} from "../src/transform";

const ts = Date.now();
const zeroUsage = {
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 0,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

const user = (content: string): UserMessage => ({ role: "user", content, timestamp: ts });

const assistant = (text: string, opts?: Partial<AssistantMessage>): AssistantMessage => ({
  role: "assistant",
  content: [{ type: "text", text }],
  api: "kiro-api",
  provider: "kiro",
  model: "test",
  usage: zeroUsage,
  stopReason: "stop",
  timestamp: ts,
  ...opts,
});

const toolResult = (id: string, text: string, isError = false): ToolResultMessage => ({
  role: "toolResult",
  toolCallId: id,
  toolName: "t",
  content: [{ type: "text", text }],
  isError,
  timestamp: ts,
});

describe("truncate", () => {
  it("returns input unchanged below limit", () => {
    expect(truncate("short", 100)).toBe("short");
  });
  it("truncates above limit with marker", () => {
    const r = truncate("a".repeat(100), 50);
    expect(r).toContain("[TRUNCATED]");
    expect(r.length).toBeLessThan(100);
  });
  it("preserves start and end", () => {
    const r = truncate(`START${"x".repeat(100)}END`, 30);
    expect(r.startsWith("START")).toBe(true);
    expect(r.endsWith("END")).toBe(true);
  });
});

describe("normalizeMessages", () => {
  it("drops errored assistant messages", () => {
    const msgs: Message[] = [user("hi"), assistant("oops", { stopReason: "error" }), user("retry")];
    expect(normalizeMessages(msgs)).toHaveLength(2);
  });
  it("drops aborted assistant messages", () => {
    expect(
      normalizeMessages([user("hi"), assistant("x", { stopReason: "aborted" })]),
    ).toHaveLength(1);
  });
  it("keeps successful assistant messages", () => {
    expect(normalizeMessages([user("hi"), assistant("ok")])).toHaveLength(2);
  });
});

describe("getContentText", () => {
  it("reads string user content", () => {
    expect(getContentText(user("hello"))).toBe("hello");
  });
  it("reads tool result", () => {
    expect(getContentText(toolResult("tc1", "result"))).toBe("result");
  });
  it("concatenates thinking + text", () => {
    const msg = assistant("");
    msg.content = [
      { type: "thinking", thinking: "hmm" },
      { type: "text", text: "answer" },
    ];
    expect(getContentText(msg)).toBe("hmmanswer");
  });
});

describe("convertToolsToKiro", () => {
  it("wraps pi tools in toolSpecification", () => {
    const params = Type.Object({ cmd: Type.String() });
    const tools: Tool[] = [
      {
        name: "bash",
        description: "Run cmd",
        parameters: params,
      },
    ];
    const r = convertToolsToKiro(tools);
    expect(r[0]?.toolSpecification.name).toBe("bash");
    expect(r[0]?.toolSpecification.inputSchema.json).toEqual(params);
  });
});

describe("convertImagesToKiro", () => {
  it("derives format from mime", () => {
    expect(convertImagesToKiro([{ mimeType: "image/png", data: "b64" }])).toEqual([
      { format: "png", source: { bytes: "b64" } },
    ]);
  });
  it("falls back to png for malformed mime", () => {
    expect(convertImagesToKiro([{ mimeType: "weird", data: "b64" }])).toEqual([
      { format: "png", source: { bytes: "b64" } },
    ]);
  });
});

describe("buildHistory", () => {
  it("returns empty history for single user", () => {
    const { history } = buildHistory([user("Hello")], "M");
    expect(history).toHaveLength(0);
  });

  it("prepends system prompt to first user message", () => {
    const msgs: Message[] = [user("first"), assistant("reply"), user("second")];
    const { history, systemPrepended } = buildHistory(msgs, "M", "Be helpful");
    expect(systemPrepended).toBe(true);
    expect(history[0]?.userInputMessage?.content).toMatch(/^Be helpful/);
  });

  it("uses origin: KIRO_CLI", () => {
    const msgs: Message[] = [user("first"), assistant("reply"), user("second")];
    const { history } = buildHistory(msgs, "M");
    expect(history[0]?.userInputMessage?.origin).toBe("KIRO_CLI");
  });

  it("converts assistant tool calls to toolUses", () => {
    const a = assistant("");
    a.content = [{ type: "toolCall", id: "tc1", name: "bash", arguments: { cmd: "ls" } }];
    const msgs: Message[] = [user("go"), a, toolResult("tc1", "ok"), user("next")];
    const { history } = buildHistory(msgs, "M");
    const entry = history.find((h) => h.assistantResponseMessage?.toolUses);
    expect(entry?.assistantResponseMessage?.toolUses?.[0]?.name).toBe("bash");
  });

  it("batches consecutive tool results", () => {
    const a = assistant("");
    a.content = [
      { type: "toolCall", id: "tc1", name: "a", arguments: {} },
      { type: "toolCall", id: "tc2", name: "b", arguments: {} },
    ];
    const msgs: Message[] = [
      user("go"),
      a,
      toolResult("tc1", "r1"),
      toolResult("tc2", "r2"),
      user("next"),
    ];
    const { history } = buildHistory(msgs, "M");
    const entry = history.find(
      (h) => h.userInputMessage?.userInputMessageContext?.toolResults,
    );
    expect(entry?.userInputMessage?.userInputMessageContext?.toolResults).toHaveLength(2);
  });

  it("truncates tool results over TOOL_RESULT_LIMIT", () => {
    const a = assistant("");
    a.content = [{ type: "toolCall", id: "tc1", name: "a", arguments: {} }];
    const msgs: Message[] = [
      user("go"),
      a,
      toolResult("tc1", "x".repeat(TOOL_RESULT_LIMIT + 1000)),
      user("next"),
    ];
    const { history } = buildHistory(msgs, "M");
    const entry = history.find(
      (h) => h.userInputMessage?.userInputMessageContext?.toolResults,
    );
    const text = entry?.userInputMessage?.userInputMessageContext?.toolResults?.[0]?.content[0]?.text ?? "";
    expect(text).toContain("[TRUNCATED]");
  });

  it("merges consecutive user messages (no synthetic padding)", () => {
    const msgs: Message[] = [user("first"), user("second"), assistant("reply"), user("third")];
    const { history } = buildHistory(msgs, "M");
    expect(JSON.stringify(history)).not.toContain('"Continue"');
    expect(history[0]?.userInputMessage?.content).toContain("first");
    expect(history[0]?.userInputMessage?.content).toContain("second");
  });

  it("merges tool results into previous user message", () => {
    const a = assistant("");
    a.content = [{ type: "toolCall", id: "tc1", name: "a", arguments: {} }];
    const msgs: Message[] = [user("go"), user("more"), a, toolResult("tc1", "ok"), user("next")];
    const { history } = buildHistory(msgs, "M");
    expect(JSON.stringify(history)).not.toContain('"Continue"');
  });

  it("maintains user/assistant alternation via merging", () => {
    const msgs: Message[] = [
      user("a"),
      user("b"),
      user("c"),
      assistant("reply"),
      user("d"),
    ];
    const { history } = buildHistory(msgs, "M");
    for (let i = 0; i < history.length - 1; i++) {
      const curr = history[i];
      const next = history[i + 1];
      if (curr?.userInputMessage) expect(next?.assistantResponseMessage).toBeDefined();
      if (curr?.assistantResponseMessage) expect(next?.userInputMessage).toBeDefined();
    }
  });

  it("serializes thinking blocks into assistant content", () => {
    const a = assistant("");
    a.content = [
      { type: "thinking", thinking: "reasoning" },
      { type: "text", text: "answer" },
    ];
    const msgs: Message[] = [user("q"), a, user("followup")];
    const { history } = buildHistory(msgs, "M");
    const arm = history.find((h) => h.assistantResponseMessage);
    expect(arm?.assistantResponseMessage?.content).toContain("<thinking>reasoning</thinking>");
    expect(arm?.assistantResponseMessage?.content).toContain("answer");
  });

  it("drops empty assistant messages with no content and no tool uses", () => {
    const a = assistant("");
    a.content = [];
    const msgs: Message[] = [user("q"), a, user("followup")];
    const { history } = buildHistory(msgs, "M");
    expect(history.find((h) => h.assistantResponseMessage)).toBeUndefined();
  });
});
