// Reuse REA's format-aware checks, policy preservation, backups and readback,
// supplying the suite launcher instead of REA's package entrypoint.
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import {
  clientConfigurationAligned,
  configureClientConfiguration,
} from "../node_modules/rea-agents/dist/application/SetupClientConfiguration.js";
import {
  explicitSetupRegistrationEnvironment,
} from "../node_modules/rea-agents/dist/application/SetupRegistrationEnvironment.js";
import { failedConfigurationMessage } from "../node_modules/rea-agents/dist/application/SetupClients.js";

export async function registration({ operation, clients, command, environment = {} }) {
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
