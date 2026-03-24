const state = {
  wallet: null,
  notes: [],
  lastCommit: null,
};

const el = {
  walletState: document.querySelector("#walletState"),
  connectWallet: document.querySelector("#connectWallet"),
  genDemo: document.querySelector("#genDemo"),
  commitForm: document.querySelector("#commitForm"),
  revealForm: document.querySelector("#revealForm"),
  scanForm: document.querySelector("#scanForm"),
  spendForm: document.querySelector("#spendForm"),
  commitOut: document.querySelector("#commitOut"),
  revealOut: document.querySelector("#revealOut"),
  spendOut: document.querySelector("#spendOut"),
  scanList: document.querySelector("#scanList"),
  activity: document.querySelector("#activity"),
};

const hex = {
  fromBytes: (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join(""),
  toBytes: (h) => {
    const clean = h.trim().replace(/^0x/, "");
    if (clean.length % 2 !== 0) throw new Error("Hex invalido");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i += 1) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  },
};

const utf8 = new TextEncoder();

const sha256 = async (...parts) => {
  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const merged = new Uint8Array(totalLen);
  let cursor = 0;
  for (const p of parts) {
    merged.set(p, cursor);
    cursor += p.length;
  }
  const digest = await crypto.subtle.digest("SHA-256", merged);
  return new Uint8Array(digest);
};

const random32 = () => crypto.getRandomValues(new Uint8Array(32));

const toLeU64 = (n) => {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(n), true);
  return new Uint8Array(view.buffer);
};

const fakePubkeyBytes = async (input) => {
  return sha256(utf8.encode(input));
};

const log = (msg) => {
  const row = document.createElement("div");
  row.className = "activity-item";
  row.textContent = `${new Date().toLocaleTimeString()}  ${msg}`;
  el.activity.prepend(row);
};

const short = (value, left = 8, right = 6) => {
  if (!value || value.length < left + right + 2) return value;
  return `${value.slice(0, left)}...${value.slice(-right)}`;
};

const connectWallet = async () => {
  if (!window.solana || !window.solana.isPhantom) {
    el.walletState.textContent = "Wallet: Phantom no disponible";
    log("Phantom no detectada. Se mantiene modo local.");
    return;
  }
  const res = await window.solana.connect();
  state.wallet = res.publicKey.toString();
  el.walletState.textContent = `Wallet: ${short(state.wallet, 10, 8)}`;
  log("Wallet conectada con Phantom.");
};

const createCommit = async (event) => {
  event.preventDefault();

  const recipient = document.querySelector("#recipient").value.trim();
  const amount = Number(document.querySelector("#amount").value);
  const nonce = Number(document.querySelector("#nonce").value);

  if (!recipient || amount <= 0 || nonce <= 0) return;

  const recipientBlinding = random32();
  const amountBlinding = random32();
  const sharedSecretHash = random32();
  const senderEphemeralPub = random32();

  const recipientBytes = await fakePubkeyBytes(recipient);
  const recipientCommitment = await sha256(
    recipientBytes,
    recipientBlinding,
    sharedSecretHash
  );
  const amountCommitment = await sha256(
    toLeU64(amount),
    amountBlinding,
    sharedSecretHash
  );
  const scanTag = await sha256(senderEphemeralPub, sharedSecretHash);
  const ghostPdaSeed = await sha256(utf8.encode(recipient), toLeU64(nonce));
  const spendAuthOpening = random32();
  const spendAuthCommitment = await sha256(ghostPdaSeed, spendAuthOpening);

  const note = {
    id: crypto.randomUUID(),
    recipient,
    amount,
    nonce,
    recipientCommitment,
    amountCommitment,
    recipientBlinding,
    amountBlinding,
    sharedSecretHash,
    senderEphemeralPub,
    scanTag,
    spendAuthOpening,
    spendAuthCommitment,
    ghostPdaSeed,
  };

  state.notes.unshift(note);
  state.lastCommit = note;

  el.commitOut.textContent = JSON.stringify(
    {
      recipientCommitment: hex.fromBytes(recipientCommitment),
      amountCommitment: hex.fromBytes(amountCommitment),
      scanTag: hex.fromBytes(scanTag),
      spendAuthCommitment: hex.fromBytes(spendAuthCommitment),
      ghostPaymentPda: hex.fromBytes(ghostPdaSeed),
    },
    null,
    2
  );

  document.querySelector("#sharedHash").value = hex.fromBytes(sharedSecretHash);
  document.querySelector("#recipientBlind").value = hex.fromBytes(recipientBlinding);
  document.querySelector("#amountBlind").value = hex.fromBytes(amountBlinding);
  document.querySelector("#ghostPda").value = hex.fromBytes(ghostPdaSeed);
  document.querySelector("#spendOpening").value = hex.fromBytes(spendAuthOpening);

  log("Compromiso creado localmente (listo para enviar a Anchor).");
};

const revealCommit = async (event) => {
  event.preventDefault();
  if (!state.lastCommit) {
    el.revealOut.textContent = "No hay compromiso previo.";
    return;
  }

  try {
    const shared = hex.toBytes(document.querySelector("#sharedHash").value);
    const rBlind = hex.toBytes(document.querySelector("#recipientBlind").value);
    const aBlind = hex.toBytes(document.querySelector("#amountBlind").value);

    const recipientBytes = await fakePubkeyBytes(state.lastCommit.recipient);
    const rc = await sha256(recipientBytes, rBlind, shared);
    const ac = await sha256(toLeU64(state.lastCommit.amount), aBlind, shared);

    const recipientOk =
      hex.fromBytes(rc) === hex.fromBytes(state.lastCommit.recipientCommitment);
    const amountOk =
      hex.fromBytes(ac) === hex.fromBytes(state.lastCommit.amountCommitment);

    el.revealOut.textContent = JSON.stringify(
      {
        recipientCommitmentMatch: recipientOk,
        amountCommitmentMatch: amountOk,
      },
      null,
      2
    );

    log("Reveal validado en frontend.");
  } catch (err) {
    el.revealOut.textContent = `Error: ${err.message}`;
  }
};

const scanNotes = async (event) => {
  event.preventDefault();

  const scanInput = document.querySelector("#scanPrivate").value.trim();
  if (!scanInput) return;

  const scanPrivate = hex.toBytes(scanInput);
  const matches = [];

  for (const note of state.notes) {
    const syntheticShared = await sha256(scanPrivate, note.senderEphemeralPub);
    const syntheticHash = await sha256(syntheticShared, toLeU64(note.nonce));
    const recomputedTag = await sha256(note.senderEphemeralPub, syntheticHash);
    if (hex.fromBytes(recomputedTag) === hex.fromBytes(note.scanTag)) {
      matches.push(note);
    }
  }

  el.scanList.innerHTML = "";
  if (matches.length === 0) {
    const li = document.createElement("li");
    li.textContent = "Sin coincidencias";
    el.scanList.append(li);
  } else {
    for (const m of matches) {
      const li = document.createElement("li");
      li.textContent = `note ${m.id.slice(0, 6)} • amount ${m.amount}`;
      el.scanList.append(li);
    }
  }

  log(`Scan completado: ${matches.length} coincidencias.`);
};

const deriveNullifier = async (event) => {
  event.preventDefault();

  try {
    const pda = hex.toBytes(document.querySelector("#ghostPda").value);
    const opening = hex.toBytes(document.querySelector("#spendOpening").value);
    const nullifier = await sha256(pda, opening, utf8.encode("nullifier"));

    el.spendOut.textContent = JSON.stringify(
      {
        nullifier: hex.fromBytes(nullifier),
        spendInstruction: "spend_from_vault",
      },
      null,
      2
    );

    log("Nullifier derivado para spend desde vault.");
  } catch (err) {
    el.spendOut.textContent = `Error: ${err.message}`;
  }
};

const fillDemo = async () => {
  document.querySelector("#recipient").value = "stealth_receiver_demo";
  document.querySelector("#amount").value = "42000";
  document.querySelector("#nonce").value = String(Math.floor(Date.now() / 1000));
  document.querySelector("#scanPrivate").value = hex.fromBytes(random32());
  log("Datos demo generados.");
};

el.connectWallet.addEventListener("click", connectWallet);
el.genDemo.addEventListener("click", fillDemo);
el.commitForm.addEventListener("submit", createCommit);
el.revealForm.addEventListener("submit", revealCommit);
el.scanForm.addEventListener("submit", scanNotes);
el.spendForm.addEventListener("submit", deriveNullifier);

fillDemo();
log("Sakura Bento UI lista.");
