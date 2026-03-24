use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;
use anchor_spl::token::{transfer, Token, TokenAccount, Transfer};

declare_id!("Fg6PaFpoGXkYsidMpWxTWqkY3bQzQ4mXxvLw6L8x8F8k");

#[program]
pub mod pagos_invisibles_solana {
	use super::*;

	pub fn create_ghost_payment(
		ctx: Context<CreateGhostPayment>,
		hashed_recipient: [u8; 32],
		amount_commitment: [u8; 32],
		ephemeral_pubkey: [u8; 32],
		scan_tag: [u8; 32],
		nonce: u64,
	) -> Result<()> {
		let ghost_payment = &mut ctx.accounts.ghost_payment;
		ghost_payment.payer = ctx.accounts.signer.key();
		ghost_payment.hashed_recipient = hashed_recipient;
		ghost_payment.amount_commitment = amount_commitment;
		ghost_payment.ephemeral_pubkey = ephemeral_pubkey;
		ghost_payment.scan_tag = scan_tag;
		ghost_payment.nonce = nonce;
		ghost_payment.revealed = false;
		ghost_payment.revealed_recipient = Pubkey::default();
		ghost_payment.revealed_amount = 0;
		ghost_payment.vault_token_account = Pubkey::default();
		ghost_payment.vault_deposit_amount = 0;
		ghost_payment.spent = false;

		emit!(PaymentCommitted {
			ghost_payment: ghost_payment.key(),
			payer: ghost_payment.payer,
			nonce,
		});

		Ok(())
	}

	pub fn create_ghost_payment_with_vault(
		ctx: Context<CreateGhostPaymentWithVault>,
		hashed_recipient: [u8; 32],
		amount_commitment: [u8; 32],
		ephemeral_pubkey: [u8; 32],
		scan_tag: [u8; 32],
		nonce: u64,
		vault_deposit_amount: u64,
	) -> Result<()> {
		require!(vault_deposit_amount > 0, GhostPayError::InvalidVaultDepositAmount);

		let cpi_accounts = Transfer {
			from: ctx.accounts.signer_token_account.to_account_info(),
			to: ctx.accounts.vault_token_account.to_account_info(),
			authority: ctx.accounts.signer.to_account_info(),
		};
		let cpi_program = ctx.accounts.token_program.to_account_info();
		let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
		transfer(cpi_ctx, vault_deposit_amount)?;

		let ghost_payment = &mut ctx.accounts.ghost_payment;
		ghost_payment.payer = ctx.accounts.signer.key();
		ghost_payment.hashed_recipient = hashed_recipient;
		ghost_payment.amount_commitment = amount_commitment;
		ghost_payment.ephemeral_pubkey = ephemeral_pubkey;
		ghost_payment.scan_tag = scan_tag;
		ghost_payment.nonce = nonce;
		ghost_payment.revealed = false;
		ghost_payment.revealed_recipient = Pubkey::default();
		ghost_payment.revealed_amount = 0;
		ghost_payment.vault_token_account = ctx.accounts.vault_token_account.key();
		ghost_payment.vault_deposit_amount = vault_deposit_amount;
		ghost_payment.spent = false;

		emit!(PaymentCommitted {
			ghost_payment: ghost_payment.key(),
			payer: ghost_payment.payer,
			nonce,
		});

		Ok(())
	}

	pub fn reveal_payment(
		ctx: Context<RevealPayment>,
		recipient: Pubkey,
		recipient_blinding: [u8; 32],
		amount: u64,
		amount_blinding: [u8; 32],
	) -> Result<()> {
		let ghost_payment = &mut ctx.accounts.ghost_payment;

		let recipient_commitment = hashv(&[recipient.as_ref(), &recipient_blinding]).to_bytes();
		require!(
			recipient_commitment == ghost_payment.hashed_recipient,
			GhostPayError::RecipientCommitmentMismatch
		);

		let amount_le = amount.to_le_bytes();
		let amount_commitment = hashv(&[&amount_le, &amount_blinding]).to_bytes();
		require!(
			amount_commitment == ghost_payment.amount_commitment,
			GhostPayError::AmountCommitmentMismatch
		);

		ghost_payment.revealed = true;
		ghost_payment.revealed_recipient = recipient;
		ghost_payment.revealed_amount = amount;

		emit!(PaymentRevealed {
			ghost_payment: ghost_payment.key(),
			revealer: ctx.accounts.signer.key(),
			recipient,
			amount,
		});

		Ok(())
	}

	pub fn consume_nullifier(ctx: Context<ConsumeNullifier>, nullifier: [u8; 32]) -> Result<()> {
		let ghost_payment = &mut ctx.accounts.ghost_payment;

		require!(!ghost_payment.spent, GhostPayError::GhostPaymentAlreadySpent);
		require!(
			ghost_payment.payer == ctx.accounts.signer.key()
				|| ghost_payment.revealed_recipient == ctx.accounts.signer.key(),
			GhostPayError::UnauthorizedSpendAttempt
		);

		let nullifier_record = &mut ctx.accounts.nullifier_record;
		nullifier_record.nullifier = nullifier;
		nullifier_record.ghost_payment = ghost_payment.key();
		nullifier_record.owner = ctx.accounts.signer.key();
		nullifier_record.created_at_slot = Clock::get()?.slot;

		ghost_payment.spent = true;

		emit!(NullifierConsumed {
			ghost_payment: ghost_payment.key(),
			nullifier,
			owner: ctx.accounts.signer.key(),
		});

		Ok(())
	}
}

#[derive(Accounts)]
#[instruction(_hashed_recipient: [u8; 32], _amount_commitment: [u8; 32], _ephemeral_pubkey: [u8; 32], _scan_tag: [u8; 32], nonce: u64)]
pub struct CreateGhostPayment<'info> {
	#[account(
		init,
		payer = signer,
		space = 8 + GhostPayment::INIT_SPACE,
		seeds = [b"ghost_payment", signer.key().as_ref(), &nonce.to_le_bytes()],
		bump
	)]
	pub ghost_payment: Account<'info, GhostPayment>,
	#[account(mut)]
	pub signer: Signer<'info>,
	pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_hashed_recipient: [u8; 32], _amount_commitment: [u8; 32], _ephemeral_pubkey: [u8; 32], _scan_tag: [u8; 32], nonce: u64)]
pub struct CreateGhostPaymentWithVault<'info> {
	#[account(
		init,
		payer = signer,
		space = 8 + GhostPayment::INIT_SPACE,
		seeds = [b"ghost_payment", signer.key().as_ref(), &nonce.to_le_bytes()],
		bump
	)]
	pub ghost_payment: Account<'info, GhostPayment>,
	#[account(mut)]
	pub signer: Signer<'info>,
	#[account(mut)]
	pub signer_token_account: Account<'info, TokenAccount>,
	#[account(mut)]
	pub vault_token_account: Account<'info, TokenAccount>,
	pub token_program: Program<'info, Token>,
	pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevealPayment<'info> {
	#[account(mut)]
	pub ghost_payment: Account<'info, GhostPayment>,
	pub signer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(nullifier: [u8; 32])]
pub struct ConsumeNullifier<'info> {
	#[account(mut)]
	pub ghost_payment: Account<'info, GhostPayment>,
	#[account(
		init,
		payer = signer,
		space = 8 + NullifierRecord::INIT_SPACE,
		seeds = [b"nullifier", &nullifier],
		bump
	)]
	pub nullifier_record: Account<'info, NullifierRecord>,
	#[account(mut)]
	pub signer: Signer<'info>,
	pub system_program: Program<'info, System>,
}

#[account]
pub struct GhostPayment {
	pub payer: Pubkey,
	pub hashed_recipient: [u8; 32],
	pub amount_commitment: [u8; 32],
	pub ephemeral_pubkey: [u8; 32],
	pub scan_tag: [u8; 32],
	pub nonce: u64,
	pub revealed: bool,
	pub revealed_recipient: Pubkey,
	pub revealed_amount: u64,
	pub vault_token_account: Pubkey,
	pub vault_deposit_amount: u64,
	pub spent: bool,
}

impl GhostPayment {
	pub const INIT_SPACE: usize = 32 + 32 + 32 + 32 + 32 + 8 + 1 + 32 + 8 + 32 + 8 + 1;
}

#[account]
pub struct NullifierRecord {
	pub nullifier: [u8; 32],
	pub ghost_payment: Pubkey,
	pub owner: Pubkey,
	pub created_at_slot: u64,
}

impl NullifierRecord {
	pub const INIT_SPACE: usize = 32 + 32 + 32 + 8;
}

#[event]
pub struct PaymentCommitted {
	pub ghost_payment: Pubkey,
	pub payer: Pubkey,
	pub nonce: u64,
}

#[event]
pub struct PaymentRevealed {
	pub ghost_payment: Pubkey,
	pub revealer: Pubkey,
	pub recipient: Pubkey,
	pub amount: u64,
}

#[event]
pub struct NullifierConsumed {
	pub ghost_payment: Pubkey,
	pub nullifier: [u8; 32],
	pub owner: Pubkey,
}

#[error_code]
pub enum GhostPayError {
	#[msg("The recipient opening does not match the stored commitment.")]
	RecipientCommitmentMismatch,
	#[msg("The amount opening does not match the stored commitment.")]
	AmountCommitmentMismatch,
	#[msg("Vault deposit amount must be greater than zero.")]
	InvalidVaultDepositAmount,
	#[msg("This ghost payment has already been spent.")]
	GhostPaymentAlreadySpent,
	#[msg("Signer is not authorized to consume this nullifier.")]
	UnauthorizedSpendAttempt,
}
