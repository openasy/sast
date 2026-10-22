import { describe, expect, it } from "vitest";
import { normalizePath, parseSarif, SarifError } from "./sarif.ts";
import { sarif } from "./test-app.ts";

const parse = (...r: Parameters<typeof sarif>) => parseSarif(JSON.parse(sarif(...r)));

describe("parseSarif", () => {
  it("reads rule, place, message and code", () => {
    const { tool, findings } = parse({ rule: "js.eval", level: "error", path: "src/a.js", line: 7, code: "eval(x)", message: "eval of input" });
    expect(tool).toBe("opengrep");
    expect(findings).toEqual([
      { fingerprint: expect.stringMatching(/^[0-9a-f]{32}$/), ruleId: "js.eval", severity: "high", path: "src/a.js", line: 7, message: "eval of input", snippet: "eval(x)" },
    ]);
  });

  it("takes severity from security-severity first, then from the level", () => {
    const sev = (r: Parameters<typeof sarif>[0]) => parse(r).findings[0]!.severity;
    expect(sev({ rule: "a", path: "a", score: 9.8 })).toBe("critical");
    expect(sev({ rule: "a", path: "a", score: 7.5, level: "note" })).toBe("high");
    expect(sev({ rule: "a", path: "a", score: 5 })).toBe("medium");
    expect(sev({ rule: "a", path: "a", score: 2 })).toBe("low");
    expect(sev({ rule: "a", path: "a", level: "error" })).toBe("high");
    expect(sev({ rule: "a", path: "a", level: "warning" })).toBe("medium");
    expect(sev({ rule: "a", path: "a", level: "note" })).toBe("low");
  });

  it("reads the score from the rule when the result has none", () => {
    const log = JSON.parse(sarif({ rule: "r1", path: "a" }));
    log.runs[0].tool.driver.rules = [{ id: "r1", properties: { "security-severity": "9.1" } }];
    expect(parseSarif(log).findings[0]!.severity).toBe("critical");
  });

  it("leaves out results the tool marked as suppressed, and results without a file", () => {
    const log = JSON.parse(sarif({ rule: "a", path: "a" }, { rule: "b", path: "b", suppressed: true }));
    log.runs[0].results.push({ ruleId: "c", message: { text: "no place" } });
    expect(parseSarif(log).findings.map((f) => f.ruleId)).toEqual(["a"]);
  });

  it("keeps a finding's fingerprint when its line moves, and tells apart two copies of it", () => {
    const at = (line: number) => parse({ rule: "r", path: "a.py", line, code: "os.system(cmd)" }).findings[0]!.fingerprint;
    expect(at(10)).toBe(at(250));
    const twice = parse({ rule: "r", path: "a.py", line: 1, code: "os.system(cmd)" }, { rule: "r", path: "a.py", line: 9, code: "os.system(cmd)" }).findings;
    expect(twice[1]!.fingerprint).toBe(`${twice[0]!.fingerprint}-2`);
    // Whitespace in the code does not matter; the rule and the file do.
    expect(parse({ rule: "r", path: "a.py", code: "os.system(  cmd )" }).findings[0]!.fingerprint).not.toBe(at(1));
    expect(parse({ rule: "r", path: "b.py", code: "os.system(cmd)" }).findings[0]!.fingerprint).not.toBe(at(1));
    expect(parse({ rule: "r", path: "a.py", code: "os.system(\n  cmd)" }).findings[0]!.fingerprint).toBe(parse({ rule: "r", path: "a.py", code: "os.system( cmd)" }).findings[0]!.fingerprint);
  });

  it("refuses what is not SARIF 2.1", () => {
    expect(() => parseSarif([])).toThrow(SarifError);
    expect(() => parseSarif({ hello: 1 })).toThrow(SarifError);
    expect(() => parseSarif({ version: "1.0.0", runs: [] })).toThrow(/not supported/);
    expect(parseSarif({ version: "2.1.0", runs: [] })).toEqual({ tool: "unknown", findings: [] });
  });
});

describe("normalizePath", () => {
  it("gives the path the repository knows", () => {
    expect(normalizePath("file:///src/a.js")).toBe("src/a.js");
    expect(normalizePath("./src/a%20b.js")).toBe("src/a b.js");
    expect(normalizePath("src\\win\\a.js")).toBe("src/win/a.js");
  });
});
