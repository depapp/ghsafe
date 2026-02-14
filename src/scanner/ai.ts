import OpenAI from "openai";
import { Finding } from "../report/types.js";

export async function analyzeWithAI(
  findings: Finding[],
  apiKey: string
): Promise<string> {
  const openai = new OpenAI({ apiKey });

  const findingSummary = findings
    .slice(0, 20) // limit to top 20 findings
    .map(
      (f) =>
        `[${f.severity}] ${f.category} in ${f.file}:${f.line}\n  ${f.description}\n  Code:\n${f.snippet}`
    )
    .join("\n\n");

  const response = await openai.chat.completions.create({
    model: "gpt-4o-mini",
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
