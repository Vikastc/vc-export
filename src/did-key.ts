import base58 from 'bs58';
import {
    mnemonicToMiniSecret,
    ed25519PairFromSeed,
} from '@polkadot/util-crypto';

export async function convertToDidKey(
    mnemonic: string,
) {
    try {
        const seed = mnemonicToMiniSecret(mnemonic);

        const generateDidComponents = (
            prefix: Uint8Array,
            publicKey: Uint8Array,
        ) => {
            const multicodecPrefixedKey = new Uint8Array([
                ...prefix,
                ...publicKey,
            ]);
            const encodedKey = base58.encode(multicodecPrefixedKey);
            const did = `did:key:z${encodedKey}`;
            const verificationMethod = `${did}#z${encodedKey}`;
            return { did, verificationMethod, encodedKey };
        };

        let did;

        const { publicKey } = ed25519PairFromSeed(seed);

        const { did: edDid } = generateDidComponents(
            new Uint8Array([0xed, 0x01]),
            publicKey,
        );

        did = edDid;

        return { did };
    } catch (error) {
        console.error('error: ', error);
        throw new Error('Did or key not generated');
    }
}
