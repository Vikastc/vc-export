import * as Cord from '@cord.network/sdk';
import 'dotenv/config';

import {
    addEd5519Proof,
    buildEd25519VcFromContent,
    makePresentation,
    statementEntryToAnchorHash,
    updateEd25519Proof,
    updateEd25519VcFromContent,
} from '../../src/vc';
import { convertToDidKey } from '../../src/did-key';

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

    /* schema */
    let newSchemaContent = require('./schema2.json');

    console.log(`\n❄️  Statement Creation `);

    let newCredContent = await buildEd25519VcFromContent(
        newSchemaContent,
        {
            email: 'alice@dhiway.com',
            fullName: 'Alice',
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
    const statementEntry = await statementEntryToAnchorHash(
        newCredContent,
        issuerDid,
        {
            spaceUri: space.uri,
        },
    );
    console.log('statementEntry: ', statementEntry);

    // Anchor VC hash to chain
    const statement = await Cord.Statement.dispatchRegisterToChain(
        statementEntry,
        issuerDid.uri,
        authorIdentity,
        space.authorization,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
    );

    console.log(`✅ Statement element registered - ${statement}`);

    // Add proof and sign
    let vc = await addEd5519Proof(
        newCredContent,
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
            type: 'Ed25519',
            spaceUri: space.uri,
            // schemaUri,
            statement,
            needSDR: true,
            needStatementProof: true,
            did: didIssuer?.did,
        },
    );

    console.log(JSON.stringify(vc, null, 2));

    // Verify VC
    // await verifyVC(vc);

    const holderKeys = Cord.Utils.Keys.generateKeypairs(
        holderMnemonic,
        'sr25519',
    );

    console.log(`\n* Generating VP.....`);

    let vp = await makePresentation(
        [vc],
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
    // await verifyVP(vp);

    // Step:5 Update Verifiable credential
    console.log(`\n* Statement updation`);

    // validUntil can be a field of choice , have set it to a month for this example
    const oneMonthFromNow = new Date();
    oneMonthFromNow.setMonth(oneMonthFromNow.getMonth() + 1);
    const validUntil = oneMonthFromNow.toISOString();

    let updatedCredContent = await updateEd25519VcFromContent(
        {
            email: 'bob@dhiway.com',
            fullName: 'Bob',
            courseName: 'Masters in Data Analytics (Dhiway) ',
            instituteName: 'Hogwarts University',
            instituteLogo: '',
            dateOfCompletion: new Date().toISOString(),
            scoreAchieved: '480/500',
        },
        vc,
        validUntil,
    );

    // Document hash anchor on chain
    const updatedStatementEntry = await statementEntryToAnchorHash(
        updatedCredContent,
        issuerDid,
        {
            call: 'update',
            spaceUri: space.uri,
        },
        statement,
    );

    console.log('updatedStatementEntry: ', updatedStatementEntry);

    const updatedStatement = await Cord.Statement.dispatchUpdateToChain(
        updatedStatementEntry,
        issuerDid.uri,
        authorIdentity,
        space.authorization,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
    );

    console.log(`✅ UpdatedStatement element registered - ${updatedStatement}`);

    let updatedVc = await updateEd25519Proof(
        updatedStatement,
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
            type: 'Ed25519',
            spaceUri: space.uri,
            // schemaUri,
            needSDR: true,
            needStatementProof: true,
            did: didIssuer?.did,
        },
    );

    console.dir(updatedVc, {
        depth: null,
        colors: true,
    });

    // Verify VC
    // await verifyVC(updatedVc);
}

main()
    .then(() => console.log('\nBye! 👋 👋 👋 '))
    .finally(Cord.disconnect);

process.on('SIGINT', async () => {
    console.log('\nBye! 👋 👋 👋 \n');
    Cord.disconnect();
    process.exit(0);
});
