import { execFileSync } from "child_process";

const SERVICE = "com.raycast.2fas-engine";
const ACCOUNT = "vault-key";
const POWERSHELL = "powershell.exe";

const VAULT_TYPE = "Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime";
const CRED_TYPE = "Windows.Security.Credentials.PasswordCredential,Windows.Security.Credentials,ContentType=WindowsRuntime";

export class KeychainAuthCancelled extends Error {
  constructor() {
    super("Authentication cancelled by user");
    this.name = "KeychainAuthCancelled";
  }
}

export class VaultKeyCorrupted extends Error {
  constructor() {
    super("Vault key has invalid length. Keychain entry may be corrupted.");
    this.name = "VaultKeyCorrupted";
  }
}

function runPS(script: string): string {
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  return execFileSync(POWERSHELL, ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], {
    stdio: ["ignore", "pipe", "pipe"],
  })
    .toString()
    .trim();
}

export function storeVaultKey(key: Buffer): void {
  const password = key.toString("base64");
  const script = `
$vault = [Activator]::CreateInstance([type]"${VAULT_TYPE}")
try { $old = $vault.Retrieve("${SERVICE}", "${ACCOUNT}"); $vault.Remove($old) } catch {}
$cred = [Activator]::CreateInstance([type]"${CRED_TYPE}", [object[]]@("${SERVICE}", "${ACCOUNT}", "${password}"))
$vault.Add($cred)
`;
  try {
    runPS(script);
  } catch (error: unknown) {
    const execError = error as { stderr?: Buffer };
    throw new Error(execError.stderr?.toString().trim() || "Failed to store vault key");
  }
}

export function retrieveVaultKey(): Buffer {
  const script = `
$vault = [Activator]::CreateInstance([type]"${VAULT_TYPE}")
$cred = $vault.Retrieve("${SERVICE}", "${ACCOUNT}")
$cred.RetrievePassword()
Write-Output $cred.Password
`;
  let result: string;
  try {
    result = runPS(script);
  } catch (error: unknown) {
    if (error instanceof KeychainAuthCancelled) throw error;
    const execError = error as { stderr?: Buffer };
    const stderr = execError.stderr?.toString() ?? "";
    if (stderr.includes("cancelled") || stderr.includes("0x800704C7")) {
      throw new KeychainAuthCancelled();
    }
    throw new Error("Failed to retrieve vault key");
  }
  const key = Buffer.from(result, "base64");
  if (key.length !== 32) {
    throw new VaultKeyCorrupted();
  }
  return key;
}

export function deleteVaultKey(): void {
  const script = `
$vault = [Activator]::CreateInstance([type]"${VAULT_TYPE}")
try { $cred = $vault.Retrieve("${SERVICE}", "${ACCOUNT}"); $vault.Remove($cred) } catch {}
`;
  try {
    runPS(script);
  } catch {
    // Key may not exist
  }
}

export function isVaultKeyStored(): boolean {
  const script = `
$vault = [Activator]::CreateInstance([type]"${VAULT_TYPE}")
try { $vault.Retrieve("${SERVICE}", "${ACCOUNT}") | Out-Null; Write-Output "true" } catch { Write-Output "false" }
`;
  try {
    return runPS(script) === "true";
  } catch {
    return false;
  }
}
