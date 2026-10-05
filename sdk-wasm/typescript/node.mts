import bindings from '../generated/node/mosaic_sdk_wasm.cjs';
import { createMosaicSdk } from './index.js';
export * from './index.js';
export const mosaic = createMosaicSdk(bindings);
