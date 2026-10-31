import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { registration } from "./agent-registration.mjs";

async function fixture(t, format = "toml", name = "codex") {
  const dir = await mkdtemp(new URL("../work/registration-test-", import.meta.url));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const configPath = join(dir, format === "toml" ? "config.toml" : "config.json");
  const command = [join(dir, "suite-launcher"), "mcp"];
  const client = { name, format, configPath };
  const request = { clients: [client], command, environment: {} };
  const current = async () => (await registration({ ...request, operation: "inspect" }))[0].current;
  const configure = () => registration({ ...request, operation: "configure" });
  return { configPath, command, request, current, configure };
}

test("repairs missing Codex timeouts and provider environment without losing policy", async (t) => {
  const f = await fixture(t);
  await writeFile(f.configPath, `# Keep this comment\nmodel = "keep-model"\n[mcp_servers.rea]\ncommand = ${JSON.stringify(f.command[0])}\nargs = ["mcp"]\ndefault_tools_approval_mode = "prompt"\n[mcp_servers.rea.env]\nUSER_SETTING = "keep"\n[mcp_servers.other]\ncommand = "keep-other-server"\n`);
  f.request.environment = { GHIDRA_INSTALL_DIR: "/suite/ghidra" };
  assert.equal(await f.current(), false);
  await f.configure();
  assert.equal(await f.current(), true);
  const repaired = await readFile(f.configPath, "utf8");
  for (const value of ["Keep this comment", "keep-model", "keep-other-server", "prompt", "USER_SETTING", "/suite/ghidra"]) {
    assert.ok(repaired.includes(value), value);
  }
  assert.match(repaired, /startup_timeout_sec\s*=/);
  assert.match(repaired, /tool_timeout_sec\s*=/);
  await f.configure();
  assert.equal(await readFile(f.configPath, "utf8"), repaired);
});

test("repairs an outdated JSON registration and keeps unrelated settings", async (t) => {
  const f = await fixture(t, "json", "cursor");
  await writeFile(f.configPath, JSON.stringify({ theme: "keep", mcpServers: { other: { command: "keep" }, rea: { command: "/old/rea", args: ["mcp"] } } }));
  assert.equal(await f.current(), false);
  await f.configure();
  assert.equal(await f.current(), true);
  const config = JSON.parse(await readFile(f.configPath, "utf8"));
  assert.equal(config.theme, "keep");
  assert.equal(config.mcpServers.other.command, "keep");
  assert.equal(config.mcpServers.rea.command, f.command[0]);
});

test("writes a PowerShell launcher with all arguments", async (t) => {
  const f = await fixture(t, "json", "cursor");
  f.command.splice(0, f.command.length, "pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\\suite\\rea.ps1", "mcp");
  await f.configure();
  assert.equal(await f.current(), true);
  const config = JSON.parse(await readFile(f.configPath, "utf8"));
  assert.deepEqual([config.mcpServers.rea.command, ...config.mcpServers.rea.args], f.command);
});

test("leaves malformed existing configuration untouched and reports failure", async (t) => {
  const f = await fixture(t);
  const broken = "[mcp_servers.rea\n";
  await writeFile(f.configPath, broken);
  assert.equal(await f.current(), false);
  await assert.rejects(f.configure(), /could not be verified/);
  assert.equal(await readFile(f.configPath, "utf8"), broken);
});
