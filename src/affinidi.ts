import express from 'express';
import {
    ed25519PairFromSeed,
    mnemonicToMiniSecret,
} from '@polkadot/util-crypto';
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020';
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020';
import base58 from 'bs58';
// import {
//     Secp256k1Key,
//     Secp256k1Signature,
// } from '@affinidi/tiny-lds-ecdsa-secp256k1-2019';
import { sign, purposes } from 'jsonld-signatures';
// import { v4 as uuidv4 } from 'uuid';
// import { secp256k1 } from 'ethereum-cryptography/secp256k1.js';
import { VerifiableCredential } from './types';

const mnemonic =
    'test walk nut penalty hip pave soap entry language right filter choice';

const vcTemplate: any = {
    '@context': [
        'https://www.w3.org/2018/credentials/v1',
        {
            credentialSchema: {
                '@id': 'https://www.w3.org/2018/credentials#credentialSchema',
                '@type': '@id',
            },
            email: {
                '@id': 'schema-id:email',
                '@type': 'https://schema.org/Text',
            },
            fullName: {
                '@id': 'schema-id:fullName',
                '@type': 'https://schema.org/Text',
            },
            courseName: {
                '@id': 'schema-id:courseName',
                '@type': 'https://schema.org/Text',
            },
            instituteName: {
                '@id': 'schema-id:instituteName',
                '@type': 'https://schema.org/Text',
            },
            instituteLogo: {
                '@id': 'schema-id:instituteLogo',
                '@type': 'https://schema.org/Text',
            },
            dateOfCompletion: {
                '@id': 'schema-id:dateOfCompletion',
                '@type': 'https://schema.org/Text',
            },
            scoreAchieved: {
                '@id': 'schema-id:score',
                '@type': 'https://schema.org/Text',
            },
        },
    ],
    type: ['VerifiableCredential'],
};

async function signCredential(
    vc: VerifiableCredential,
    did: any,
    type: string,
) {
    try {
        let signedDoc;
        if (type === 'secp256k1') {
            // /* suite is very important */
            // const suite = new Secp256k1Signature({
            //     key,
            //     date: new Date().toISOString(),
            // });
            // console.log('in secp256k1', suite);
            // /* this is used for signing */
            // signedDoc = await jsigs.sign(
            //     { ...vc },
            //     {
            //         suite,
            //         documentLoader: async (url: any) => {
            //             if (url.startsWith('https://')) {
            //                 /* does this always work? */
            //                 const response = await fetch(url);
            //                 const json = await response.json();
            //                 return {
            //                     contextUrl: null,
            //                     document: json,
            //                     documentUrl: url,
            //                 };
            //             }
            //         },
            //         purpose: new jsigs.purposes.AssertionProofPurpose(),
            //         compactProof: false,
            //     },
            // );
        } else if (type === 'ed25519') {
            const keyPair = await Ed25519VerificationKey2020.generate({
                controller: did,
            });

            const suite = new Ed25519Signature2020({ key: keyPair });

            try {
                signedDoc = await sign(vc, {
                    suite,
                    purpose: new purposes.AssertionProofPurpose(),
                    documentLoader: async (url: any) => {
                        console.log(`Resolving URL: ${url}`);
                        if (url.startsWith('https://')) {
                            const response = await fetch(url);
                            const json = await response.json();
                            return {
                                contextUrl: null,
                                document: json,
                                documentUrl: url,
                            };
                        }
                    },
                });
            } catch (error) {
                console.error('Signing Error:', error);
            }
        }

        return signedDoc;
    } catch (error) {
        console.error('err: ', error);
        throw new Error('Error generating signed doc');
    }
}

async function generateVC(content: any, holderDid: string) {
    // let vc = { ...vcTemplate };
    // const seed = mnemonicToMiniSecret(mnemonic);
    // const privateKey = seed.slice(0, 32);
    // const publicKey = secp256k1.getPublicKey(privateKey, true);
    // const multicodecPrefixedKey = new Uint8Array([0xe7, 0x01, ...publicKey]);
    // const encodedKey = base58.encode(multicodecPrefixedKey);
    // const verificationMethod = `did:key:z${encodedKey}#z${encodedKey}`;
    // const did = `did:key:z${encodedKey}`;
    // const key = new Secp256k1Key({
    //     id: verificationMethod,
    //     controller: did,
    //     publicKeyHex: Buffer.from(publicKey).toString('hex'),
    //     privateKeyHex: Buffer.from(privateKey).toString('hex'),
    // });
    // vc.issuanceDate = new Date().toISOString();
    // vc.holder = { id: holderDid };
    // vc.id = 'cord:' + uuidv4();
    // vc.credentialSubject = {
    //     id: holderDid,
    //     fullName: content.fullName,
    //     email: content.email,
    //     courseName: content.courseName,
    //     instituteName: content.instituteName,
    //     instituteLogo: content.instituteLogo,
    //     dateOfCompletion: content.dateOfCompletion,
    //     scoreAchieved: content.scoreAchieved,
    // };
    // vc.issuer = did;
    // const signedVC = await signCredential(vc, key, 'secp256k1');
    // const wrappedVC = {
    //     credential: signedVC,
    // };
    // console.log('For Affinidi: \n', JSON.stringify(wrappedVC, null, 2));
    // return wrappedVC;
}

async function createVcForAffinidi(
    req: express.Request,
    res: express.Response,
) {
    try {
        // const { content } = req.body;

        const content = {
            email: 'amar@dhiway.com',
            studentName: 'Amar Tumballi',
            courseName: 'Masters in Data Analytics (Dhiway) ',
            instituteName: 'Hogwarts University',
            instituteLogo: '',
            dateOfCompletion: new Date().toISOString(),
            scoreAchieved: '450/500',
            holderDid:
                'did:web:oid4vci.demo.cord.network:3zKcL2oAsvZZwFA5uPxtysk5jsai2TGx4AvrpJcBYmAwzGyN',
        };

        const holderDid = content.holderDid;

        if (!content || !holderDid) {
            return res.status(400).json({
                error: 'Invalid request. `content` and `holderDid` are required.',
            });
        }

        // Generate the Verifiable Credential
        const signedVC = await generateVC(content, holderDid);

        // Respond with the signed VC
        return res.status(200).json({
            result: {
                message: 'Verifiable Credential generated successfully',
                signedVC,
            },
        });
    } catch (error) {
        console.error('Error generating VC:', error);
        res.status(500).json({
            error: 'Failed to generate Verifiable Credential',
        });
    }
}

async function convertToDidKey(
    mnemonic: string,
    type: 'secp256k1' | 'ed25519',
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

        let key;
        let did;

        if (type === 'secp256k1') {
            // const privateKey = seed.slice(0, 32);
            // const publicKey = secp256k1.getPublicKey(privateKey, true);
            // const { did: secpDid, verificationMethod } = generateDidComponents(
            //     new Uint8Array([0xe7, 0x01]),
            //     publicKey,
            // );
            // key = new Secp256k1Key({
            //     id: verificationMethod,
            //     controller: secpDid,
            //     publicKeyHex: Buffer.from(publicKey).toString('hex'),
            //     privateKeyHex: Buffer.from(privateKey).toString('hex'),
            // });
            // did = secpDid;
        } else if (type === 'ed25519') {
            const { publicKey, secretKey: privateKey } =
                ed25519PairFromSeed(seed);

            const { did: edDid, verificationMethod } = generateDidComponents(
                new Uint8Array([0xed, 0x01]),
                publicKey,
            );

            did = edDid;
        }

        return { did };
    } catch (error) {
        console.error('error: ', error);
        throw new Error('Did or key not generated');
    }
}
