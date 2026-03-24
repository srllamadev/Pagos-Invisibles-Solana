// @ts-nocheck
// Client

const toLeU64 = (value: BN): Buffer => value.toArrayLike(Buffer, "le", 8);

const toBytes32 = (value: Uint8Array): number[] => Array.from(value);

const sha256 = (parts: Buffer[]): Uint8Array =>
	anchor.utils.sha256.hash(Buffer.concat(parts));

const deriveScanPubkey = (scanSecret: Uint8Array): Uint8Array =>
	sha256([Buffer.from(scanSecret)]);

const deriveRecipientCommitment = (
	recipient: web3.PublicKey,
	recipientBlinding: Uint8Array
): Uint8Array => sha256([recipient.toBuffer(), Buffer.from(recipientBlinding)]);

const deriveAmountCommitment = (
	amount: BN,
	amountBlinding: Uint8Array
): Uint8Array => sha256([toLeU64(amount), Buffer.from(amountBlinding)]);

const deriveScanTag = (
	scanPubkey: Uint8Array,
	ephemeralPubkey: Uint8Array,
	nonce: BN,
	recipientCommitment: Uint8Array
): Uint8Array =>
	sha256([
		Buffer.from(scanPubkey),
		Buffer.from(ephemeralPubkey),
		toLeU64(nonce),
		Buffer.from(recipientCommitment),
	]);

const createGhostCommitmentPayload = (params: {
	recipient: web3.PublicKey;
	amount: BN;
	recipientBlinding: Uint8Array;
	amountBlinding: Uint8Array;
	ephemeralPubkey: Uint8Array;
	scanPubkey: Uint8Array;
	nonce: BN;
}) => {
	const hashedRecipient = deriveRecipientCommitment(
		params.recipient,
		params.recipientBlinding
	);
	const amountCommitment = deriveAmountCommitment(
		params.amount,
		params.amountBlinding
	);
	const scanTag = deriveScanTag(
		params.scanPubkey,
		params.ephemeralPubkey,
		params.nonce,
		hashedRecipient
	);

	return {
		hashedRecipient,
		amountCommitment,
		scanTag,
	};
};

const scanForOwnedGhostPayments = async (
	scanSecret: Uint8Array,
	maxResults = 50
) => {
	const scanPubkey = deriveScanPubkey(scanSecret);
	const all = await pg.program.account.ghostPayment.all();
	const own = all
		.filter((entry: any) => {
			const account = entry.account;
			const recomputed = deriveScanTag(
				scanPubkey,
				new Uint8Array(account.ephemeralPubkey),
				account.nonce,
				new Uint8Array(account.hashedRecipient)
			);
			return Buffer.from(recomputed).equals(Buffer.from(account.scanTag));
		})
		.slice(0, maxResults);

	return own;
};

console.log("My address:", pg.wallet.publicKey.toString());
const balance = await pg.connection.getBalance(pg.wallet.publicKey);
console.log(`My balance: ${balance / web3.LAMPORTS_PER_SOL} SOL`);

const scanSecret = web3.Keypair.generate().secretKey.slice(0, 32);
const scanPubkey = deriveScanPubkey(scanSecret);

const recipient = web3.Keypair.generate().publicKey;
const amount = new BN(123456);
const nonce = new BN(Date.now());
const recipientBlinding = web3.Keypair.generate().publicKey.toBytes();
const amountBlinding = web3.Keypair.generate().publicKey.toBytes();
const ephemeralPubkey = web3.Keypair.generate().publicKey.toBytes();

const commitment = createGhostCommitmentPayload({
	recipient,
	amount,
	recipientBlinding,
	amountBlinding,
	ephemeralPubkey,
	scanPubkey,
	nonce,
});

const [ghostPaymentPda] = web3.PublicKey.findProgramAddressSync(
	[
		Buffer.from("ghost_payment"),
		pg.wallet.publicKey.toBuffer(),
		toLeU64(nonce),
	],
	pg.program.programId
);

await pg.program.methods
	.createGhostPayment(
		toBytes32(commitment.hashedRecipient),
		toBytes32(commitment.amountCommitment),
		toBytes32(ephemeralPubkey),
		toBytes32(commitment.scanTag),
		nonce
	)
	.accounts({
		ghostPayment: ghostPaymentPda,
		signer: pg.wallet.publicKey,
		systemProgram: web3.SystemProgram.programId,
	})
	.rpc();

const ownGhostPayments = await scanForOwnedGhostPayments(scanSecret);
console.log("Ghost payments matched by scan key:", ownGhostPayments.length);
