import { SafeSecurityError } from "../common/safe-error";

const PREFIX = "⟦AG:";
const MAX_TOKEN_LENGTH = 180;

export class TokenStreamParser {
  private buffer = "";

  constructor(private readonly replaceToken: (token: string) => string) {}

  feed(chunk: string): string {
    this.buffer += chunk;
    let output = "";
    while (this.buffer.length > 0) {
      const start = this.buffer.indexOf(PREFIX);
      if (start === -1) {
        const retained = longestPrefixSuffix(this.buffer);
        output += this.buffer.slice(0, this.buffer.length - retained);
        this.buffer = this.buffer.slice(this.buffer.length - retained);
        break;
      }
      output += this.buffer.slice(0, start);
      this.buffer = this.buffer.slice(start);
      const end = this.buffer.indexOf("⟧");
      if (end === -1) {
        if (this.buffer.length > MAX_TOKEN_LENGTH) throw malformedToken();
        break;
      }
      const token = this.buffer.slice(0, end + 1);
      if (token.length > MAX_TOKEN_LENGTH) throw malformedToken();
      output += this.replaceToken(token);
      this.buffer = this.buffer.slice(end + 1);
    }
    return output;
  }

  finish(): string {
    if (this.buffer.includes(PREFIX)) throw malformedToken();
    const output = this.buffer;
    this.buffer = "";
    return output;
  }
}

function longestPrefixSuffix(value: string): number {
  const maximum = Math.min(PREFIX.length - 1, value.length);
  for (let length = maximum; length > 0; length -= 1) {
    if (value.endsWith(PREFIX.slice(0, length))) return length;
  }
  return 0;
}

function malformedToken(): SafeSecurityError {
  return new SafeSecurityError(
    "AG_POLICY_TOKEN_MALFORMED",
    403,
    "The stream contained an incomplete or oversized security token",
  );
}
