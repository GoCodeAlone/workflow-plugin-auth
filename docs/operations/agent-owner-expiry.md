# Review the exact grant expiry

The native owner page defaults to **1 day**. It shows the proposed absolute UTC
expiry before confirmation and submits that same instant, without silently
recalculating it when the form is submitted. Proposed times use whole seconds.
Changing the lifetime clears confirmation and shows a new expiry; changing the
tenant also clears confirmation. An expired proposal is refused without a POST.
Select the lifetime again and review the new instant before approving.

The proposed lifetime starts when the displayed expiry is calculated. Time
spent completing the form reduces the remaining lifetime; it does not extend
the grant. Retained grants also display absolute UTC expiry, regardless of the
browser's timezone. Existing authenticated owner authorization, durable policy,
grant creation and revocation limits still apply.

For the one-day preview proposal, fresh public grant readback must establish the
actual ID, version, creation and expiry times and exact approved authority.
Approve the resulting public client profile before activation. A clock mismatch
or readback exceeding the approved one-day ceiling must stop activation and be
reconciled; do not widen the profile. This display repair creates no persistent
key, grant, credential configuration or workload activation.
