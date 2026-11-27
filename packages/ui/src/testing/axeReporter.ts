import type {FullResult, Reporter, TestCase, TestResult} from "@playwright/test/reporter";

// The run summary of spec 17.5 / T-473: the known accessibility failures (DESIGN.md Q1 to Q4) that
// were met in this run, and the `incomplete` results axe could not decide. Both are annotations that
// axe.ts adds to the test, so the list reporter prints nothing about them on its own.
export default class AxeSummary implements Reporter {
  private known = new Map<string, number>();
  private incomplete = new Map<string, number>();

  onTestEnd(test: TestCase, result: TestResult) {
    void result;
    for (const a of test.annotations) {
      const into = a.type === "axe-known" ? this.known : a.type === "axe-incomplete" ? this.incomplete : null;
      if (into && a.description) into.set(a.description, (into.get(a.description) ?? 0) + 1);
    }
  }

  onEnd(result: FullResult) {
    void result;
    const print = (title: string, from: Map<string, number>) => {
      if (from.size === 0) return;
      console.log(`\n${title} (${from.size}):`);
      for (const [line, count] of [...from].sort()) console.log(`  ${line}${count > 1 ? ` x${count}` : ""}`);
    };
    print("axe: known failures met in this run (axe-known.json, DESIGN.md Q1 to Q4)", this.known);
    print("axe: incomplete, left to a manual look", this.incomplete);
  }

  printsToStdio() {
    return false;
  }
}
