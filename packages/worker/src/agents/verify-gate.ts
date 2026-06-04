export interface VerifyResult {
  reproduced: boolean;
  output: string;
}

// The verify gate: a candidate finding is only promoted if its MINIMAL reproducer,
// re-executed deterministically, reproduces the expected signal. `reproduce` re-runs
// the exact payload (e.g. through the broker); `signal` decides whether the output
// proves the vulnerability.
export async function verifyReproduction(
  reproduce: () => Promise<string>,
  signal: (output: string) => boolean,
): Promise<VerifyResult> {
  const output = await reproduce();
  return { reproduced: signal(output), output };
}

// SSTI arithmetic oracle: a `{{a*b}}` payload should make the target reflect the
// computed product. A literal echo of the payload (no evaluation) must NOT pass.
export function sstiArithmeticSignal(a: number, b: number): (output: string) => boolean {
  const product = String(a * b);
  const payloadFragment = `${a}*${b}`;
  return (output) => output.includes(product) && !output.includes(`{{${payloadFragment}}}`);
}
