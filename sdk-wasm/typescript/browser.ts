import init, * as bindings from '../generated/web/mosaic_sdk_wasm.js';
import { createMosaicSdk } from './index.js';
export * from './index.js';
export async function initializeMosaic(input?: Parameters<typeof init>[0]) {
 await init(input);
 return createMosaicSdk(bindings);
}
