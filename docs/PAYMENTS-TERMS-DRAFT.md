# Payments wording for the Terms and Privacy pages — DRAFT, not published

**Status:** draft for the owner's review. Nothing in this file is live. The public pages
(`packages/dashboard/public/terms.html`, `privacy.html`) are unchanged, and purchases stay switched
off until `SHANNON_COMMERCE_ENABLED=1` is set.

**Why this exists:** the current Terms mention payment only in passing ("Any refund is governed by
the applicable subscription terms and law") and the Privacy Policy mentions only Stripe. The product
can now also take crypto, QR and bank-transfer payments that a person reviews by hand, and it sells
prepaid credits that expire. Both pages need to say so before purchases are turned on.

**This is not legal advice.** The wording below describes what the software does. The parts marked
**DECISION** are commercial and legal choices that only you can make; have a solicitor check the
result, especially the consumer-rights clauses.

## Decisions to make first

1. **Refunds.** The software has no automatic refund. Choose a policy: for example "unused credits
   refunded on request within 14 days of purchase", or "no refunds except where the law requires".
   If you sell to consumers (not only businesses) in the UK or EU, they normally have a 14-day right
   to cancel a digital service, which ends once the service has been fully performed with their
   agreement. Clause T3 below has a placeholder.
2. **Who you sell to.** Businesses only, or consumers too? "Businesses only" simplifies clause T3 but
   must then be true in practice (stated at checkout, and accepted by the buyer).
3. **Refund route for crypto.** Crypto payments cannot be reversed by the network. Decide whether a
   refund is paid back in the same asset to the sending address, at what exchange rate, and who
   bears the network fee.
4. **Tax.** Whether prices include VAT, and whether you issue VAT invoices. The catalog in
   `packages/dashboard/commerce.mjs` is in GBP and the prices are placeholders — confirm them.
5. **The seller's legal name and address**, which UK law requires on a page that takes payment.
6. **Version dates.** Signup records the Terms and Privacy versions a person accepted
   (`termsVersion` / `privacyVersion` in `server.mjs`, currently `2026-05-04`). When you publish new
   wording, change both the date on the page and those two values.

## Terms of Service — proposed new section "Paid scans and credits"

Insert after "3. Your API keys, your bill" and renumber the sections that follow.

> **T1. What you can buy.** You can buy fixed-price scans and packs of prepaid credits. The current
> prices are on the Pricing page. Prices are in pounds sterling. **[DECISION 4: "and include VAT" /
> "and exclude VAT, which is added at checkout where it applies".]**
>
> **T2. How credits work.** Each organization has a free daily allowance. When the allowance for the
> day is used up, the Service uses your prepaid credits. Credits belong to the organization that
> bought them and cannot be transferred or exchanged for money. **Credits expire 90 days after
> purchase.** When you hold credits from more than one purchase, the ones that expire soonest are
> used first. Buying credits does not change the rules in "Authorized use": you may still only scan
> systems you own or are authorized to test.
>
> **T3. Refunds and cancellation.** **[DECISION 1 and 2 — replace this paragraph with your policy.
> Example for business customers: "Purchases are for business use. Unused credits are refunded on
> request within 14 days of purchase; credits that have been used, and credits that have expired,
> are not refunded." If you sell to consumers, add: "If you are a consumer you have a legal right to
> cancel within 14 days. By starting a scan within that period you ask us to begin the service
> straight away, and you will pay for what has been used if you then cancel." Nothing in these Terms
> limits rights you have under consumer law that cannot be excluded.]**
>
> **T4. Paying by card.** Card payments are taken by Stripe. We do not receive or store your card
> number. Credits are added when Stripe confirms the payment.
>
> **T5. Paying by cryptocurrency, QR payment or bank transfer.** These payments are checked by a
> person, not automatically. You create an order, pay the stated amount using the order reference,
> then submit the transaction hash or payment reference. Credits are added once we have confirmed
> that the payment arrived, which is usually **[DECISION: state a time, for example "within one
> working day"]**. An order that we cannot match to a payment is rejected and no credits are added.
> You are responsible for sending the correct amount to the address or account shown for your
> order, and for any network or bank fees. A cryptocurrency payment cannot be reversed by the
> network; a payment sent to the wrong address or on the wrong network may be lost and we cannot
> recover it. **[DECISION 3: how a refund of a crypto payment is paid.]**
>
> **T6. If something goes wrong.** If credits were added by mistake, or a payment is later reversed
> or charged back, we may remove the corresponding credits. If we suspend or close an account for
> breaking these Terms, unused credits are **[DECISION 1: "forfeited" / "refunded less any amounts
> owed"]**.
>
> **T7. Seller.** Paid services are sold by **[DECISION 5: legal name, company number, registered
> address]**.

Also change the existing sentence in section 4 from "Any refund is governed by the applicable
subscription terms and law." to "Refunds are covered in section 4, Paid scans and credits." (use the
new section's number).

## Privacy Policy — proposed changes

**Section 1, "Data we collect" — add two rows to the table:**

| Data | Why | Where it is held |
|---|---|---|
| Orders and credit balance: what was bought, the amount, the date, the order reference, the payment method, and whether the order was approved | To add credits to your organization, show your balance, and keep the accounting records the law requires | Our database |
| For crypto, QR and bank-transfer payments: the transaction hash or payment reference you submit, any note you add, and which member of our staff approved or rejected the order | To match your payment to your order | Our database |

**Section 3, "Third-party providers" — replace the Stripe wording with:**

> **Stripe** processes card payments when billing is enabled. Stripe receives your card details
> directly; we receive only confirmation of the payment and a payment identifier.
>
> **Cryptocurrency networks.** If you pay in cryptocurrency, the transaction — the sending and
> receiving addresses, the amount and the time — is recorded permanently on a public blockchain.
> That record is outside our control and cannot be changed or deleted by us or by you. We do not
> link a wallet address to your identity beyond matching the transaction to your order.
>
> **Banks and regional payment apps.** If you pay by bank transfer or QR payment, your bank or
> payment app shares with our bank the details that normally accompany a payment, such as the
> account holder's name.

**Section 5, "Data retention" — add:**

> Order and payment records are kept for **[DECISION: the period your accountant requires — in the
> UK, company accounting records are generally kept for six years]**, including after an account is
> closed, because the law requires us to keep accounting records.

**Section 6, "Your rights" — add one sentence:**

> The right to erasure does not cover accounting records we are legally required to keep, or
> transactions recorded on a public blockchain, which nobody can erase.

## After you approve the wording

1. Put the final text into `terms.html` and `privacy.html` and update the dates shown on both pages.
2. Update `termsVersion` and `privacyVersion` in `packages/dashboard/server.mjs` to the same dates.
3. Only then set `SHANNON_COMMERCE_ENABLED=1`.
