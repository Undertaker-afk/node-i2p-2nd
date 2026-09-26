import { VerifiedRouterInfoStore } from './store.ts';
import { reseedRouterInfoStore, type ReseedOptions, type ReseedResult } from './reseed.ts';
import type { PersistentRouterInfoStore } from './persistent-store.ts';

/** Downloads/validates a reseed bundle, then persists every newly accepted RouterInfo atomically. */
export async function reseedPersistentRouterInfoStore(persistent: PersistentRouterInfoStore, options: ReseedOptions = {}): Promise<ReseedResult> {
  const staged = new VerifiedRouterInfoStore(persistent.maxRecords, persistent.expectedNetId);
  const result = await reseedRouterInfoStore(staged, options);
  let imported = 0;
  for (const info of staged.all()) if (await persistent.store(info)) imported++;
  return { ...result, imported };
}
