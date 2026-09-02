import { chmod, readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const EXPECTED_ROUTE = {
  pattern: 'release-health-controller.scalesmall.ai',
  custom_domain: true,
};

export async function materializeReleaseHealthControllerBootstrap(sourcePath, targetPath) {
  if (typeof sourcePath !== 'string' || sourcePath.length === 0) {
    throw new Error('Controller deployment config path is required.');
  }
  if (typeof targetPath !== 'string' || targetPath.length === 0 || targetPath === sourcePath) {
    throw new Error('A distinct bootstrap config path is required.');
  }

  const value = JSON.parse(await readFile(sourcePath, 'utf8'));
  if (value.name !== 'ssai-release-health-controller') {
    throw new Error('Controller name is invalid.');
  }
  if (value.workers_dev !== false || value.preview_urls !== false) {
    throw new Error('Controller public subdomain policy is invalid.');
  }
  if (JSON.stringify(value.routes) !== JSON.stringify([EXPECTED_ROUTE])) {
    throw new Error('Controller production domain is invalid.');
  }
  if (JSON.stringify(value.triggers?.crons) !== JSON.stringify(['* * * * *'])) {
    throw new Error('Controller production schedule is invalid.');
  }
  if (value.vars?.MODE !== 'observe') {
    throw new Error('Controller bootstrap must remain in observe mode.');
  }
  if (!Array.isArray(value.durable_objects?.bindings)
    || value.durable_objects.bindings.length !== 1
    || value.durable_objects.bindings[0]?.name !== 'SLOT_LEDGER'
    || value.durable_objects.bindings[0]?.class_name !== 'ReleaseHealthControllerObject') {
    throw new Error('Controller Durable Object binding is invalid.');
  }

  delete value.routes;
  delete value.triggers;
  await writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  await chmod(targetPath, 0o600);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 4) {
    throw new Error('Usage: materialize-release-health-controller-bootstrap.mjs <source> <target>');
  }
  await materializeReleaseHealthControllerBootstrap(process.argv[2], process.argv[3]);
}
