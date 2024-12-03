import * as Cord from '@cord.network/sdk';
import 'dotenv/config';

import {
    addEcdsaSecp256k1Proof,
    addProof,
    buildAffinidiVcFromContent,
    buildCordProof,
    buildVcFromContent,
    makePresentation,
    updateAddProof,
    updateVcFromContent,
} from '../../src/vc';
import { verifyVP, verifyVC, verifyProofElement } from '../../src/verifyUtils';
import { getCordProofForDigest } from '../../src/docs';
import { convertToDidKey, generateVC } from '../../src/affinidi';
import { calculateAffinidiVCHash, calculateVCHash } from '../../src/utils';

function getChallenge(): string {
    return Cord.Utils.UUID.generate();
}

async function main() {
    const { NETWORK_ADDRESS, ANCHOR_URI, DID_NAME } = process.env;
    const networkAddress = NETWORK_ADDRESS;
    const anchorUri = ANCHOR_URI;
    const didName = DID_NAME;
    Cord.ConfigService.set({ submitTxResolveOn: Cord.Chain.IS_IN_BLOCK });
    await Cord.connect(networkAddress as string);

    const api = Cord.ConfigService.get('api');

    // Step 1: Setup Membership
    // Setup transaction author account - CORD Account.

    console.log(`\n❄️  New Network Member`);
    const authorIdentity = Cord.Utils.Crypto.makeKeypairFromUri(
        anchorUri as string,
        'sr25519',
    );

    // Create Holder DID
    const { mnemonic: holderMnemonic, document: holderDid } =
        await Cord.Did.createDid(authorIdentity);

    // Create issuer DID
    const { mnemonic: issuerMnemonic, document: issuerDid } =
        await Cord.Did.createDid(authorIdentity);
    const issuerKeys = Cord.Utils.Keys.generateKeypairs(
        issuerMnemonic,
        'sr25519',
    );
    console.log(
        `🏛   Issuer (${issuerDid?.assertionMethod![0].type}): ${issuerDid.uri}`,
    );

    /*********************************************/

    // Issuer did:key converstion
    const didIssuer = await convertToDidKey(issuerMnemonic);
    console.log('Issuer did: ', didIssuer);

    // Holder did:key converstion
    const didHolder = await convertToDidKey(holderMnemonic);
    console.log('Holder did: ', didHolder);

    /*********************************************/

    const conformingDidDocument = Cord.Did.exportToDidDocument(
        issuerDid,
        'application/json',
    );
    console.log(' \n ✅ Identities created!');

    console.log(`\n❄️  Chain Space Creation `);
    const spaceProperties = await Cord.ChainSpace.buildFromProperties(
        issuerDid.uri,
    );

    console.log(`\n❄️  Chain Space Properties `);
    const space = await Cord.ChainSpace.dispatchToChain(
        spaceProperties,
        issuerDid.uri,
        authorIdentity,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
    );

    console.log(`\n❄️  Chain Space Approval `);
    await Cord.ChainSpace.sudoApproveChainSpace(authorIdentity, space.uri, 100);
    console.log(`✅  Chain Space Approved`);

    /* schema */

    let newSchemaContent = require('./schema2.json');
    // let newSchemaName =
    //     newSchemaContent.title + ':' + Cord.Utils.UUID.generate();
    // newSchemaContent.title = newSchemaName;
    // console.log('newSchemaContent: ', newSchemaContent);

    // let schemaProperties = Cord.Schema.buildFromProperties(
    //     newSchemaContent,
    //     space.uri,
    //     issuerDid.uri,
    // );

    // console.log('schemaProperties: ', schemaProperties);
    // const schemaUri = await Cord.Schema.dispatchToChain(
    //     schemaProperties.schema,
    //     issuerDid.uri,
    //     authorIdentity,
    //     space.authorization,
    //     async ({ data }) => ({
    //         signature: issuerKeys.authentication.sign(data),
    //         keyType: issuerKeys.authentication.type,
    //     }),
    // );
    // console.log(`✅ Schema - ${schemaUri} - added!`);

    // Step 4: Delegate creates a new Verifiable Document
    console.log(`\n❄️  Statement Creation `);

    // let newCredContent = await buildVcFromContent(
    //     schemaProperties.schema,
    //     {
    //         name: 'Alice',
    //         age: 29,
    //         id: '123456789987654321',
    //         country: 'India',
    //         address: {
    //             street: 'a',
    //             pin: 54032,
    //             location: {
    //                 state: 'karnataka',
    //             },
    //         },
    //     },
    //     issuerDid,
    //     holderDid.uri,
    //     {
    //         spaceUri: space.uri,
    //         schemaUri: schemaUri,
    //     },
    // );

    let newCredContent = await buildAffinidiVcFromContent(
        newSchemaContent,
        {
            email: 'amar@dhiway.com',
            fullName: 'Amar Tumballi',
            courseName: 'Masters in Data Analytics (Dhiway) ',
            instituteName: 'Hogwarts University',
            instituteLogo: '',
            dateOfCompletion: new Date().toISOString(),
            scoreAchieved: '450/500',
        },
        didIssuer,
        didHolder,
        {
            spaceUri: space.uri,
        },
    );

    // Document hash anchor on chain
    const credHash = calculateAffinidiVCHash(newCredContent, undefined);
    const statementEntry = buildCordProof(
        credHash,
        space.uri,
        issuerDid.uri,
        undefined,
    );
    console.dir(credHash, { colors: true, depth: null });

    // Add proof
    let vcDoc = await addEcdsaSecp256k1Proof(
        newCredContent,
        async (data) => ({
            signature: issuerKeys.assertionMethod.sign(data),
            keyType: issuerKeys.assertionMethod.type,
            keyUri: `${issuerDid.uri}${
                issuerDid.assertionMethod![0].id
            }` as Cord.DidResourceUri,
        }),
        issuerDid,
        api,
        {
            type: 'affinidi',
            spaceUri: space.uri,
            // schemaUri,
            needSDR: true,
            needStatementProof: true,
            key: didIssuer.key,
        },
    );

    // let vc = await addProof(
    //     newCredContent,
    //     async (data) => ({
    //         signature: await issuerKeys.assertionMethod.sign(data),
    //         keyType: issuerKeys.assertionMethod.type,
    //         keyUri: `${issuerDid.uri}${
    //             issuerDid.assertionMethod![0].id
    //         }` as Cord.DidResourceUri,
    //     }),
    //     issuerDid,
    //     api,
    //     {
    //         spaceUri: space.uri,
    //         schemaUri,
    //         needSDR: true,
    //         needStatementProof: true,
    //     },
    // );

    console.dir(vcDoc.vc, {
        depth: null,
        colors: true,
    });

    let docHash;
    if (vcDoc.options.type === 'affinidi') {
        docHash = statementEntry;
        console.log('in affinidi', docHash);
    } else {
        docHash = vcDoc.vc.proof[1];
    }

    const statement = await Cord.Statement.dispatchRegisterToChain(
        docHash,
        issuerDid.uri,
        authorIdentity,
        space.authorization,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
    );

    console.log(`✅ Statement element registered - ${statement}`);

    await verifyVC(vcDoc.vc);

    const holderKeys = Cord.Utils.Keys.generateKeypairs(
        holderMnemonic,
        'sr25519',
    );

    let vp = await makePresentation(
        [vcDoc.vc],
        holderDid,
        async (data) => ({
            signature: holderKeys.assertionMethod.sign(data),
            keyType: holderKeys.assertionMethod.type,
            keyUri: `${holderDid.uri}${
                holderDid.assertionMethod![0].id
            }` as Cord.DidResourceUri,
        }),
        getChallenge(),
        api,
        {
            needSDR: true,
            selectedFields: ['age', 'address'],
        },
    );
    console.dir(vp, { colors: true, depth: null });
    /* VP verification would 'throw' an error in case of error */
    await verifyVP(vp);

    // Step:5 Update Verifiable credential
    console.log(`\n* Statement updation`);

    // validUntil can be a field of choice , have set it to a month for this example
    const oneMonthFromNow = new Date();
    oneMonthFromNow.setMonth(oneMonthFromNow.getMonth() + 1);
    const validUntil = oneMonthFromNow.toISOString();

    let updatedCredContent = await updateVcFromContent(
        {
            name: 'Bob',
            age: 30,
            id: '362734238278237',
            country: 'India',
            address: {
                street: 'a',
                pin: 54032,
                location: {
                    state: 'karnataka',
                },
            },
        },
        vcDoc.vc,
        validUntil,
    );

    let updatedVc = await updateAddProof(
        vcDoc.vc.proof[1].elementUri,
        updatedCredContent,
        async (data) => ({
            signature: await issuerKeys.assertionMethod.sign(data),
            keyType: issuerKeys.assertionMethod.type,
            keyUri: `${issuerDid.uri}${
                issuerDid.assertionMethod![0].id
            }` as Cord.DidResourceUri,
        }),
        issuerDid,
        api,
        {
            spaceUri: space.uri,
            // schemaUri,
            needSDR: true,
            needStatementProof: true,
        },
    );

    console.dir(updatedVc, {
        depth: null,
        colors: true,
    });

    const updatedStatement = await Cord.Statement.dispatchUpdateToChain(
        updatedVc.proof[1],
        issuerDid.uri,
        authorIdentity,
        space.authorization,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
    );

    console.log(`✅ UpdatedStatement element registered - ${updatedStatement}`);

    await verifyVC(updatedVc);
}

main()
    .then(() => console.log('\nBye! 👋 👋 👋 '))
    .finally(Cord.disconnect);

process.on('SIGINT', async () => {
    console.log('\nBye! 👋 👋 👋 \n');
    Cord.disconnect();
    process.exit(0);
});
