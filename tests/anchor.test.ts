// @ts-nocheck
// No imports needed: web3, anchor, pg and more are globally available

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
): Uint8Array => sha256([Buffer.from(ephemeralPubkey), Buffer.from(sharedSecretHash)]);

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

const findVaultAuthorityPda = (
  ghostPayment: web3.PublicKey
): web3.PublicKey =>
  web3.PublicKey.findProgramAddressSync(
    [Buffer.from("vault_authority"), ghostPayment.toBuffer()],
    pg.program.programId
  )[0];

describe("GhostPay commitments", () => {
  it("commits via ECDH and reveals recipient + amount", async () => {
    const recipient = web3.Keypair.generate().publicKey;
    const nonce = new BN(Date.now());
    const amount = new BN(250_000);

    const recipientBlinding = web3.Keypair.generate().publicKey.toBytes();
    const amountBlinding = web3.Keypair.generate().publicKey.toBytes();
    const receiverScanPrivate = random32();
    const receiverScanPublic = deriveX25519Pubkey(receiverScanPrivate);
    const senderEphemeralPrivate = random32();
    const senderEphemeralPublic = deriveX25519Pubkey(senderEphemeralPrivate);

    const senderSharedSecret = deriveSharedSecret(
      senderEphemeralPrivate,
      receiverScanPublic
    );
    const receiverSharedSecret = deriveSharedSecret(
      receiverScanPrivate,
      senderEphemeralPublic
    );
    assert(
      Buffer.from(senderSharedSecret).equals(Buffer.from(receiverSharedSecret))
    );

    const sharedSecretHash = deriveSharedSecretHash(senderSharedSecret, nonce);
    const recipientCommitment = deriveRecipientCommitment(
      recipient,
      recipientBlinding,
      sharedSecretHash
    );
    const amountCommitment = deriveAmountCommitment(
      amount,
      amountBlinding,
      sharedSecretHash
    );
    const scanTag = deriveScanTag(senderEphemeralPublic, sharedSecretHash);

    const ghostPaymentPda = findGhostPaymentPda(nonce);
    const spendAuthOpening = random32();
    const spendAuthCommitment = deriveSpendAuthCommitment(
      ghostPaymentPda,
      spendAuthOpening
    );

    await pg.program.methods
      .createGhostPayment(
        toBytes32(recipientCommitment),
        toBytes32(amountCommitment),
        toBytes32(senderEphemeralPublic),
        toBytes32(scanTag),
        toBytes32(spendAuthCommitment),
        nonce
      )
      .accounts({
        ghostPayment: ghostPaymentPda,
        signer: pg.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();

    await pg.program.methods
      .revealPayment(
        recipient,
        toBytes32(recipientBlinding),
        toBytes32(sharedSecretHash),
        amount,
        toBytes32(amountBlinding)
      )
      .accounts({
        ghostPayment: ghostPaymentPda,
        signer: pg.wallet.publicKey,
      })
      .rpc();

    const ghostPayment = await pg.program.account.ghostPayment.fetch(
      ghostPaymentPda
    );

    assert(ghostPayment.revealed === true);
    assert(ghostPayment.revealedAmount.eq(amount));
    assert(ghostPayment.revealedRecipient.equals(recipient));
    assert(Buffer.from(ghostPayment.scanTag).equals(Buffer.from(scanTag)));

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

    const ghostPaymentAfterSpend = await pg.program.account.ghostPayment.fetch(
      ghostPaymentPda
    );
    assert(ghostPaymentAfterSpend.spent === true);
  });

  it("creates ghost payment with SPL vault deposit", async () => {
    const nonce = new BN(Date.now() + 77);
    const amount = new BN(50_000);
    const receiver = web3.Keypair.generate().publicKey;

    const receiverScanPrivate = random32();
    const receiverScanPublic = deriveX25519Pubkey(receiverScanPrivate);
    const senderEphemeralPrivate = random32();
    const senderEphemeralPublic = deriveX25519Pubkey(senderEphemeralPrivate);
    const sharedSecret = deriveSharedSecret(senderEphemeralPrivate, receiverScanPublic);
    const sharedSecretHash = deriveSharedSecretHash(sharedSecret, nonce);

    const recipientBlinding = random32();
    const amountBlinding = random32();

    const recipientCommitment = deriveRecipientCommitment(
      receiver,
      recipientBlinding,
      sharedSecretHash
    );
    const amountCommitment = deriveAmountCommitment(
      amount,
      amountBlinding,
      sharedSecretHash
    );
    const scanTag = deriveScanTag(senderEphemeralPublic, sharedSecretHash);

    const ghostPaymentPda = findGhostPaymentPda(nonce);
    const spendAuthOpening = random32();
    const spendAuthCommitment = deriveSpendAuthCommitment(
      ghostPaymentPda,
      spendAuthOpening
    );

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
      200_000
    );

    const vaultAuthorityPda = findVaultAuthorityPda(ghostPaymentPda);

    const vaultAta = await splToken.getOrCreateAssociatedTokenAccount(
      pg.connection,
      pg.wallet.keypair,
      mint,
      vaultAuthorityPda,
      true
    );

    const recipientStealth = web3.Keypair.generate().publicKey;
    const recipientAta = await splToken.getOrCreateAssociatedTokenAccount(
      pg.connection,
      pg.wallet.keypair,
      mint,
      recipientStealth
    );

    const vaultDeposit = new BN(25_000);

    await pg.program.methods
      .createGhostPaymentWithVault(
        toBytes32(recipientCommitment),
        toBytes32(amountCommitment),
        toBytes32(senderEphemeralPublic),
        toBytes32(scanTag),
        toBytes32(spendAuthCommitment),
        nonce,
        vaultDeposit
      )
      .accounts({
        ghostPayment: ghostPaymentPda,
        signer: pg.wallet.publicKey,
        signerTokenAccount: signerAta.address,
        vaultAuthority: vaultAuthorityPda,
        vaultTokenAccount: vaultAta.address,
        tokenMint: mint,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();

    const note = await pg.program.account.ghostPayment.fetch(ghostPaymentPda);
    assert(note.vaultTokenAccount.equals(vaultAta.address));
    assert(note.vaultAuthority.equals(vaultAuthorityPda));
    assert(note.tokenMint.equals(mint));
    assert(note.vaultDepositAmount.eq(vaultDeposit));

    const nullifier = deriveNullifier(ghostPaymentPda, spendAuthOpening);
    const [nullifierRecordPda] = web3.PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier"), Buffer.from(nullifier)],
      pg.program.programId
    );

    await pg.program.methods
      .spendFromVault(
        toBytes32(nullifier),
        toBytes32(spendAuthOpening),
        vaultDeposit
      )
      .accounts({
        ghostPayment: ghostPaymentPda,
        nullifierRecord: nullifierRecordPda,
        signer: pg.wallet.publicKey,
        vaultAuthority: vaultAuthorityPda,
        vaultTokenAccount: vaultAta.address,
        recipientTokenAccount: recipientAta.address,
        tokenMint: mint,
        tokenProgram: splToken.TOKEN_PROGRAM_ID,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();

    const vaultAfter = await splToken.getAccount(pg.connection, vaultAta.address);
    const recipientAfter = await splToken.getAccount(
      pg.connection,
      recipientAta.address
    );
    const noteAfterSpend = await pg.program.account.ghostPayment.fetch(ghostPaymentPda);

    assert(vaultAfter.amount === BigInt(0));
    assert(recipientAfter.amount === BigInt(vaultDeposit.toString()));
    assert(noteAfterSpend.spent === true);
  });
});
