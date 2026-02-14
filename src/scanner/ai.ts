import OpenAI from "openai";
import { Finding } from "../report/types.js";

interface AIProvider {
  name: string;
  client: OpenAI;
  model: string;
}

function getAIProvider(): AIProvider {
  // Primary: GitHub Models (uses GITHUB_TOKEN)
  if (process.env.GITHUB_TOKEN) {
    return {
      name: "GitHub Models",
      client: new OpenAI({
        baseURL: "https://models.inference.ai.azure.com",
        apiKey: process.env.GITHUB_TOKEN,
      }),
      model: "gpt-4o-mini",
    };
  }

  // Fallback: OpenAI directly
  if (process.env.OPENAI_API_KEY) {
    return {
      name: "OpenAI",
      client: new OpenAI({ apiKey: process.env.OPENAI_API_KEY }),
      model: "gpt-4o-mini",
    };
  }

  throw new Error(
    "No AI provider configured. Set GITHUB_TOKEN (recommended) or OPENAI_API_KEY."
  );
}

export function getProviderHint(): string {
  if (process.env.GITHUB_TOKEN) return "GitHub Models (GITHUB_TOKEN)";
  if (process.env.OPENAI_API_KEY) return "OpenAI (OPENAI_API_KEY)";
  return "none";
}

export async function analyzeWithAI(findings: Finding[]): Promise<string> {
  const provider = getAIProvider();

  const findingSummary = findings
    .slice(0, 20) // limit to top 20 findings
    .map(
      (f) =>
        `[${f.severity}] ${f.category} in ${f.file}:${f.line}\n  ${f.description}\n  Code:\n${f.snippet}`
    )
    .join("\n\n");

  const response = await provider.client.chat.completions.create({
    model: provider.model,
    messages: [
      {
        role: "system",
        content: `You are a cybersecurity expert analyzing code for potential malicious behavior. 
You are given a list of suspicious findings from a static code analysis of a GitHub repository.
Analyze the findings and provide:
1. An overall threat assessment (is this repository likely malicious or are these false positives?)
2. The most concerning findings and why
3. Recommended actions for the user
Be concise but thorough. Format your response in clear sections.`,
      },
      {
        role: "user",
        content: `Analyze these suspicious code findings:\n\n${findingSummary}`,
      },
    ],
    max_tokens: 1000,
    temperature: 0.3,
  });

  return response.choices[0]?.message?.content ?? "AI analysis unavailable.";
}
