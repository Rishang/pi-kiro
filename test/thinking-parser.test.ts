import type {
  AssistantMessage,
  AssistantMessageEvent,
  AssistantMessageEventStream,
  ThinkingContent,
} from "@earendil-works/pi-ai";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import { describe, expect, it } from "vitest";
import { ThinkingTagParser } from "../src/thinking-parser";

function makeOutput(): AssistantMessage {
  return {
    role: "assistant",
    content: [],
    api: "kiro-api",
    provider: "kiro",
    model: "test",
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason: "stop",
    timestamp: Date.now(),
  };
}

async function collect(stream: AssistantMessageEventStream): Promise<AssistantMessageEvent[]> {
  const events: AssistantMessageEvent[] = [];
  stream.end();
  for await (const e of stream) events.push(e);
  return events;
}

describe("ThinkingTagParser", () => {
  it("splits <thinking>...</thinking> into a thinking block and text", async () => {
    const output = makeOutput();
    const stream = createAssistantMessageEventStream();
    const parser = new ThinkingTagParser(output, stream);
    parser.processChunk("<thinking>reasoning</thinking>the answer");
    parser.finalize();
    await collect(stream);
    expect(output.content).toHaveLength(2);
    expect(output.content[0]?.type).toBe("thinking");
    expect((output.content[0] as ThinkingContent).thinking).toBe("reasoning");
    expect(output.content[1]?.type).toBe("text");
  });

  it("handles tag tokens spanning chunk boundaries", async () => {
    const output = makeOutput();
    const stream = createAssistantMessageEventStream();
    const parser = new ThinkingTagParser(output, stream);
    parser.processChunk("<thin");
    parser.processChunk("king>hidden</thi");
    parser.processChunk("nking>visible");
    parser.finalize();
    await collect(stream);
    expect(output.content[0]?.type).toBe("thinking");
    expect((output.content[0] as ThinkingContent).thinking).toBe("hidden");
    expect(output.content[1]?.type).toBe("text");
  });

  it("recognizes <think>, <reasoning>, <thought> variants", async () => {
    for (const [open, close] of [
      ["<think>", "</think>"],
      ["<reasoning>", "</reasoning>"],
      ["<thought>", "</thought>"],
    ]) {
      const output = makeOutput();
      const stream = createAssistantMessageEventStream();
      const parser = new ThinkingTagParser(output, stream);
      parser.processChunk(`${open}inside${close}after`);
      parser.finalize();
      await collect(stream);
      expect(output.content[0]?.type).toBe("thinking");
      expect((output.content[0] as ThinkingContent).thinking).toBe("inside");
    }
  });

  it("appends thinking after already-emitted text (no index-corrupting splice)", async () => {
    const output = makeOutput();
    const stream = createAssistantMessageEventStream();
    const pushed: AssistantMessageEvent[] = [];
    const origPush = stream.push.bind(stream);
    stream.push = (e: AssistantMessageEvent) => {
      pushed.push(e);
      return origPush(e);
    };
    const parser = new ThinkingTagParser(output, stream);
    parser.processChunk("prefix text ");
    const textStart = pushed.find((e) => e.type === "text_start");
    expect(textStart && "contentIndex" in textStart ? textStart.contentIndex : -1).toBe(0);

    parser.processChunk("<thinking>late reasoning</thinking>");
    parser.finalize();
    await collect(stream);
    // Text was emitted first at index 0; thinking is APPENDED at index 1 — the
    // already-sent text_start/text_delta events keep their contentIndex 0, so
    // splicing would corrupt downstream ordering. Appending keeps them valid.
    expect(output.content[0]?.type).toBe("text");
    expect(output.content[1]?.type).toBe("thinking");
    const thinkingStart = pushed.find((e) => e.type === "thinking_start");
    expect(thinkingStart && "contentIndex" in thinkingStart ? thinkingStart.contentIndex : -1).toBe(1);
    // Every emitted text_delta still references index 0 (no splice corruption).
    const textDeltas = pushed.filter((e) => e.type === "text_delta");
    expect(textDeltas.length).toBeGreaterThan(0);
    expect(textDeltas.every((e) => "contentIndex" in e && e.contentIndex === 0)).toBe(true);
  });

  it("handles plain text with no thinking tags", async () => {
    const output = makeOutput();
    const stream = createAssistantMessageEventStream();
    const parser = new ThinkingTagParser(output, stream);
    parser.processChunk("just plain text");
    parser.finalize();
    await collect(stream);
    expect(output.content).toHaveLength(1);
    expect(output.content[0]?.type).toBe("text");
  });

  it("handles unterminated thinking block in finalize", async () => {
    const output = makeOutput();
    const stream = createAssistantMessageEventStream();
    const parser = new ThinkingTagParser(output, stream);
    parser.processChunk("<thinking>never closed");
    parser.finalize();
    await collect(stream);
    expect(output.content[0]?.type).toBe("thinking");
    expect((output.content[0] as ThinkingContent).thinking).toBe("never closed");
  });
});
