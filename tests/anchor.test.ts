// @ts-nocheck
// No imports needed: web3, anchor, pg and more are globally available

const toLeU64 = (value: BN): Buffer => value.toArrayLike(Buffer, "le", 8);

const toBytes32 = (value: Uint8Array): number[] => Array.from(value);

describe("GhostPay commitments", () => {
  it("commits and later reveals recipient + amount", async () => {
    const recipient = web3.Keypair.generate().publicKey;
    const nonce = new BN(Date.now());
    const amount = new BN(250_000);

    const recipientBlinding = web3.Keypair.generate().publicKey.toBytes();
    const amountBlinding = web3.Keypair.generate().publicKey.toBytes();
    const ephemeralPubkey = web3.Keypair.generate().publicKey.toBytes();

    const recipientCommitment = anchor.utils.sha256.hash(
      Buffer.concat([recipient.toBuffer(), Buffer.from(recipientBlinding)])
    );

    const amountCommitment = anchor.utils.sha256.hash(
      Buffer.concat([toLeU64(amount), Buffer.from(amountBlinding)])
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
  });
});
