import { Injectable } from "@nestjs/common";
import type { ChatMessage, ProviderMetadata } from "../common/types";
import type { LlmCompletion, LlmProvider } from "./provider.types";

@Injectable()
export class MockProvider implements LlmProvider {
  private callCount = 0;
  private lastSanitizedPrompt: string | undefined;

  complete(
    _provider: ProviderMetadata,
    messages: ChatMessage[],
  ): Promise<LlmCompletion> {
    this.callCount += 1;
    const message = [...messages]
      .reverse()
      .find((candidate) => candidate.role === "user");
    this.lastSanitizedPrompt = message?.content ?? "";
    return Promise.resolve({
      content: `Safe mock response: ${message?.content ?? ""}`,
      toolCalls: [],
    });
  }

  getCallCountForTest(): number {
    return this.callCount;
  }

  getLastSanitizedPromptForTest(): string | undefined {
    return this.lastSanitizedPrompt;
  }
}
