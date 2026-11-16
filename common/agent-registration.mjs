// Reuse REA's format-aware checks, policy preservation, backups and readback,
// supplying the suite launcher instead of REA's package entrypoint.
import { fileURLToPath } from "node:url";
import { isAbsolute, resolve } from "node:path";

// rea-agents (6.9 and later) changes a registration only when it owns it: its launcher must be
// the running entrypoint, process.argv[1], which it reads once when its modules load. The suite
// launcher owns the suite's registrations, so it becomes the entrypoint before rea-agents loads;
// any other registration, REA's own included, stays foreign and is left to the user.
let rea;
async function reaModules(command) {
  if (rea) return rea;
  if (command.length === 2 && command[1] === "mcp" && isAbsolute(command[0])) {
    process.argv[1] = command[0];
  }
  const dist = "../node_modules/rea-agents/dist/application/";
  const [configuration, environment, clients] = await Promise.all([
    import(`${dist}SetupClientConfiguration.js`),
    import(`${dist}SetupRegistrationEnvironment.js`),
    import(`${dist}SetupClients.js`),
  ]);
  rea = {
    clientConfigurationAligned: configuration.clientConfigurationAligned,
    configureClientConfiguration: configuration.configureClientConfiguration,
    explicitSetupRegistrationEnvironment: environment.explicitSetupRegistrationEnvironment,
    failedConfigurationMessage: clients.failedConfigurationMessage,
  };
  return rea;
}

export async function registration({ operation, clients, command, environment = {} }) {
  const {
    clientConfigurationAligned,
    configureClientConfiguration,
    explicitSetupRegistrationEnvironment,
    failedConfigurationMessage,
  } = await reaModules(command);
  const desiredEnvironment = {
    ...environment,
    ...explicitSetupRegistrationEnvironment(process.env),
  };
  const results = [];
  for (const client of clients) {
    if (client.format === "unsupported") {
      results.push({ name: client.name, current: false });
      continue;
    }
    if (operation === "configure") {
      const result = await configureClientConfiguration(client, desiredEnvironment, command);
      if (result.status === "failed") throw new Error(failedConfigurationMessage(result));
    } else if (operation !== "inspect") {
      throw new Error(`Unknown registration operation: ${operation}`);
    }
    const current = await clientConfigurationAligned(client, desiredEnvironment, command);
    if (operation === "configure" && !current) {
      throw new Error(`${client.name}: registration is still not current after repair`);
    }
    results.push({ name: client.name, current });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    let input = "";
    for await (const chunk of process.stdin) input += chunk;
    console.log(JSON.stringify(await registration(JSON.parse(input))));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
