import type { ChatMessage, ProviderMetadata } from "../common/types";

export interface LlmCompletion {
  content: string;
  toolCalls: Array<{ name: string; arguments: string }>;
}

export interface LlmProvider {
  complete(
    provider: ProviderMetadata,
    messages: ChatMessage[],
  ): Promise<LlmCompletion>;
}
