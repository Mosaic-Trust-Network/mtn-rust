import { mosaic, type Right } from '@mosaic-private/sdk/node';
import { initializeMosaic } from '@mosaic-private/sdk/browser';
const id: string = mosaic.deriveDid(new Uint8Array(32));
const encoded: Uint8Array = mosaic.didScale(id);
const rights: readonly Right[] = mosaic.rights();
const digest: string = mosaic.digestJson('{"n":9007199254740993}', 'blake3');
void encoded; void rights; void digest; void initializeMosaic;
// @ts-expect-error JSON text is mandatory to preserve the preimage.
mosaic.digestJson({ n: 1 });
// @ts-expect-error Unknown algorithms cannot enter the typed API.
mosaic.contentIdFromHash(new Uint8Array(32), 'md5');

const envelope = '{"content":{},"proof":{"blockHeight":1,"blockHash":"0x00"}}';
const payload: Uint8Array = mosaic.envelopeSigningPayload(envelope);
const verified: boolean = mosaic.verifyEnvelopeSignature(envelope, 'public-key', 'signature', 'key-ref');
void payload; void verified;
// @ts-expect-error Signing ports return wire signatures, not secret bytes.
mosaic.signEnvelope(envelope, 'public-key', 'key-ref', () => new Uint8Array(64));

const op: Uint8Array = mosaic.updateCommitmentOperation(id, digest, '18446744073709551615');
const operationPayload: Uint8Array = mosaic.didOperationSigningPayload(op, 'key-ref', '1');
void operationPayload;
// @ts-expect-error Numbers lose u64 precision; only decimal strings cross this boundary.
mosaic.didOperationSigningPayload(op, 'key-ref', 1);
// @ts-expect-error No private-key or raw signature bytes in the external signer port.
mosaic.signDidOperation(op, 'public-key', 'key-ref', '1', () => new Uint8Array(64));
