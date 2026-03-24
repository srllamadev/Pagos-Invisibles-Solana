// @ts-nocheck
// Client

const toLeU64 = (value: BN): Buffer => value.toArrayLike(Buffer, "le", 8);

const toBytes32 = (value: Uint8Array): number[] => Array.from(value);

const sha256 = (parts: Buffer[]): Uint8Array =>
	anchor.utils.sha256.hash(Buffer.concat(parts));

const random32 = (): Uint8Array => web3.Keypair.generate().secretKey.slice(0, 32);

const deriveX25519Pubkey = (privateKey: Uint8Array): Uint8Array =>
	nacl.scalarMult.base(privateKey);

const deriveSharedSecret = (
	privateKey: Uint8Array,
	publicKey: Uint8Array
): Uint8Array => nacl.scalarMult(privateKey, publicKey);

const deriveSharedSecretHash = (
	sharedSecret: Uint8Array,
	nonce: BN
): Uint8Array => sha256([Buffer.from(sharedSecret), toLeU64(nonce)]);

const deriveRecipientCommitment = (
	recipient: web3.PublicKey,
	recipientBlinding: Uint8Array,
	sharedSecretHash: Uint8Array
): Uint8Array =>
	sha256([
		recipient.toBuffer(),
		Buffer.from(recipientBlinding),
		Buffer.from(sharedSecretHash),
	]);

const deriveAmountCommitment = (
	amount: BN,
	amountBlinding: Uint8Array,
	sharedSecretHash: Uint8Array
): Uint8Array =>
	sha256([
		toLeU64(amount),
		Buffer.from(amountBlinding),
		Buffer.from(sharedSecretHash),
	]);

const deriveScanTag = (
	ephemeralPubkey: Uint8Array,
 	sharedSecretHash: Uint8Array
): Uint8Array =>
	sha256([
		Buffer.from(ephemeralPubkey),
		Buffer.from(sharedSecretHash),
	]);

const deriveSpendAuthCommitment = (
	ghostPayment: web3.PublicKey,
	spendAuthOpening: Uint8Array
): Uint8Array => sha256([ghostPayment.toBuffer(), Buffer.from(spendAuthOpening)]);

const deriveNullifier = (
	ghostPayment: web3.PublicKey,
	spendAuthOpening: Uint8Array
): Uint8Array =>
	sha256([
		ghostPayment.toBuffer(),
		Buffer.from(spendAuthOpening),
		Buffer.from("nullifier"),
	]);

const findGhostPaymentPda = (nonce: BN): web3.PublicKey =>
	web3.PublicKey.findProgramAddressSync(
		[
			Buffer.from("ghost_payment"),
			pg.wallet.publicKey.toBuffer(),
			toLeU64(nonce),
		],
		pg.program.programId
	)[0];

const createGhostCommitmentPayload = (params: {
	recipient: web3.PublicKey;
	amount: BN;
	recipientBlinding: Uint8Array;
	amountBlinding: Uint8Array;
	ephemeralPubkey: Uint8Array;
	sharedSecretHash: Uint8Array;
	nonce: BN;
}) => {
	const hashedRecipient = deriveRecipientCommitment(
		params.recipient,
		params.recipientBlinding,
		params.sharedSecretHash
	);
	const amountCommitment = deriveAmountCommitment(
		params.amount,
		params.amountBlinding,
		params.sharedSecretHash
	);
	const scanTag = deriveScanTag(params.ephemeralPubkey, params.sharedSecretHash);

	return {
		hashedRecipient,
		amountCommitment,
		scanTag,
	};
};

const scanForOwnedGhostPayments = async (
	scanPrivateKey: Uint8Array,
	maxResults = 50
) => {
	const all = await pg.program.account.ghostPayment.all();
	const own = all
		.filter((entry: any) => {
			const account = entry.account;
			const sharedSecret = deriveSharedSecret(
				scanPrivateKey,
				new Uint8Array(account.ephemeralPubkey)
			);
			const sharedSecretHash = deriveSharedSecretHash(sharedSecret, account.nonce);
			const recomputed = deriveScanTag(
				new Uint8Array(account.ephemeralPubkey),
				sharedSecretHash
			);
			return Buffer.from(recomputed).equals(Buffer.from(account.scanTag));
		})
		.slice(0, maxResults);

	return own;
};

console.log("My address:", pg.wallet.publicKey.toString());
const balance = await pg.connection.getBalance(pg.wallet.publicKey);
console.log(`My balance: ${balance / web3.LAMPORTS_PER_SOL} SOL`);

const receiverScanPrivate = random32();
const receiverScanPublic = deriveX25519Pubkey(receiverScanPrivate);
const senderEphemeralPrivate = random32();
const senderEphemeralPublic = deriveX25519Pubkey(senderEphemeralPrivate);

const recipient = web3.Keypair.generate().publicKey;
const amount = new BN(123456);
const nonce = new BN(Date.now());
const recipientBlinding = web3.Keypair.generate().publicKey.toBytes();
const amountBlinding = web3.Keypair.generate().publicKey.toBytes();

const sharedSecret = deriveSharedSecret(
	senderEphemeralPrivate,
	receiverScanPublic
);
const sharedSecretHash = deriveSharedSecretHash(sharedSecret, nonce);

const ghostPaymentPda = findGhostPaymentPda(nonce);
const spendAuthOpening = random32();
const spendAuthCommitment = deriveSpendAuthCommitment(
	ghostPaymentPda,
	spendAuthOpening
);

const commitment = createGhostCommitmentPayload({
	recipient,
	amount,
	recipientBlinding,
	amountBlinding,
	ephemeralPubkey: senderEphemeralPublic,
	sharedSecretHash,
	nonce,
});

const mint = await splToken.createMint(
	pg.connection,
	pg.wallet.keypair,
	pg.wallet.publicKey,
	null,
	6
);

const signerAta = await splToken.getOrCreateAssociatedTokenAccount(
	pg.connection,
	pg.wallet.keypair,
	mint,
	pg.wallet.publicKey
);

await splToken.mintTo(
	pg.connection,
	pg.wallet.keypair,
	mint,
	signerAta.address,
	pg.wallet.publicKey,
	500_000
);

const vaultOwner = web3.Keypair.generate();
await pg.connection.requestAirdrop(vaultOwner.publicKey, web3.LAMPORTS_PER_SOL);

const vaultAta = await splToken.getOrCreateAssociatedTokenAccount(
	pg.connection,
	pg.wallet.keypair,
	mint,
	vaultOwner.publicKey
);

const vaultDeposit = new BN(75_000);

await pg.program.methods
	.createGhostPaymentWithVault(
		toBytes32(commitment.hashedRecipient),
		toBytes32(commitment.amountCommitment),
		toBytes32(senderEphemeralPublic),
		toBytes32(commitment.scanTag),
		toBytes32(spendAuthCommitment),
		nonce,
		vaultDeposit
	)
	.accounts({
		ghostPayment: ghostPaymentPda,
		signer: pg.wallet.publicKey,
		signerTokenAccount: signerAta.address,
		vaultTokenAccount: vaultAta.address,
		tokenProgram: splToken.TOKEN_PROGRAM_ID,
		systemProgram: web3.SystemProgram.programId,
	})
	.rpc();

const ownGhostPayments = await scanForOwnedGhostPayments(receiverScanPrivate);
console.log("Ghost payments matched by scan key:", ownGhostPayments.length);

const nullifier = deriveNullifier(ghostPaymentPda, spendAuthOpening);
const [nullifierRecordPda] = web3.PublicKey.findProgramAddressSync(
	[Buffer.from("nullifier"), Buffer.from(nullifier)],
	pg.program.programId
);

await pg.program.methods
	.consumeNullifier(toBytes32(nullifier), toBytes32(spendAuthOpening))
	.accounts({
		ghostPayment: ghostPaymentPda,
		nullifierRecord: nullifierRecordPda,
		signer: pg.wallet.publicKey,
		systemProgram: web3.SystemProgram.programId,
	})
	.rpc();
