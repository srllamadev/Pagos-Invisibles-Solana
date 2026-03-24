// @ts-nocheck
// No imports needed: web3, anchor, pg and more are globally available

const toLeU64 = (value: BN): Buffer => value.toArrayLike(Buffer, "le", 8);

const toBytes32 = (value: Uint8Array): number[] => Array.from(value);

const deriveScanPubkey = (scanSecret: Uint8Array): Uint8Array =>
  anchor.utils.sha256.hash(Buffer.from(scanSecret));

const deriveScanTag = (
  scanPubkey: Uint8Array,
  ephemeralPubkey: Uint8Array,
  nonce: BN,
  hashedRecipient: Uint8Array
): Uint8Array =>
  anchor.utils.sha256.hash(
    Buffer.concat([
      Buffer.from(scanPubkey),
      Buffer.from(ephemeralPubkey),
      toLeU64(nonce),
      Buffer.from(hashedRecipient),
    ])
  );

describe("GhostPay commitments", () => {
  it("commits and later reveals recipient + amount", async () => {
    const recipient = web3.Keypair.generate().publicKey;
    const nonce = new BN(Date.now());
    const amount = new BN(250_000);

    const recipientBlinding = web3.Keypair.generate().publicKey.toBytes();
    const amountBlinding = web3.Keypair.generate().publicKey.toBytes();
    const ephemeralPubkey = web3.Keypair.generate().publicKey.toBytes();
    const scanSecret = web3.Keypair.generate().secretKey.slice(0, 32);
    const scanPubkey = deriveScanPubkey(scanSecret);

    const recipientCommitment = anchor.utils.sha256.hash(
      Buffer.concat([recipient.toBuffer(), Buffer.from(recipientBlinding)])
    );

    const amountCommitment = anchor.utils.sha256.hash(
      Buffer.concat([toLeU64(amount), Buffer.from(amountBlinding)])
    );

    const scanTag = deriveScanTag(
      scanPubkey,
      ephemeralPubkey,
      nonce,
      recipientCommitment
    );

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
        toBytes32(recipientCommitment),
        toBytes32(amountCommitment),
        toBytes32(ephemeralPubkey),
        toBytes32(scanTag),
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

    const nullifier = anchor.utils.sha256.hash(
      Buffer.concat([Buffer.from(ephemeralPubkey), toLeU64(nonce), toLeU64(amount)])
    );

    const [nullifierRecordPda] = web3.PublicKey.findProgramAddressSync(
      [Buffer.from("nullifier"), Buffer.from(nullifier)],
      pg.program.programId
    );

    await pg.program.methods
      .consumeNullifier(toBytes32(nullifier))
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
});
