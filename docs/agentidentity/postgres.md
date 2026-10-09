# Durable PostgreSQL service grants

`agentidentity/postgres` supplies a reusable `database/sql` adapter for
`agentidentity.Store`, `GrantManager` and `Auditor`. It persists public assertion
keys, approved tenant grants, globally consumed assertion identities, token
revocations and an immutable audit outbox. It creates no human identity,
passkey, TOTP factor, bootstrap credential, managed issuer key or private key.

```go
store, err := postgres.New(existingHostDB, reviewedSharedSchema)
// Handle err; New only validates the DB pointer and namespace. No Ping or DDL.
// Pass this SAME store to agentidentity.Options.Store and Options.Audit.
```

`New(*sql.DB, string) (*Store, error)` accepts a lowercase PostgreSQL namespace
matching `[a-z_][a-z0-9_]{0,62}`. Every runtime table reference is qualified with
that copied namespace; connection `search_path` does not select the grant store.
The host owns TLS, the pool, driver registration, credentials and lifecycle.
Production code imports no driver. Tests use the already pinned pgx driver.

The host must use **one shared schema for all grants accepted by one service
identity exchange authority**. A separate namespace per tenant would split the
global replay ledger and permit reuse of one assertion on another tenant grant.
A second preview site requires declarative `TenantConfig` and a separate,
explicitly approved grant; it requires no adapter fork or new human credential.
Creating a site or declaring its configuration never activates an agent grant.

## Typed persistence and authorization

- `GetGrant(ctx, id)` loads the full saved grant and P-256 public key. Missing or
  invalid identifiers return `ErrDenied`; corrupt/unavailable storage returns
  `ErrUnavailable`. Revoked or expired rows remain readable for management;
  service authorization rejects them using current grant and host policy.
- `CreateGrant(ctx, grant)` requires version 1, an active structurally valid
  grant, positive tenant ID, approved owner ID and a lifetime no greater than
  30 days. The database clock rejects future creation or already expired grants.
  Duplicate IDs return `ErrConflict`. The insert and committed audit event share
  one transaction. The reusable owner handler supplies `ApprovedBy` from its
  verified human resolver, never from request JSON or headers.
- `RevokeGrant(ctx, id, expectedVersion, actor, at)` locks and rechecks the
  current row, refuses stale/repeated revocation with `ErrConflict`, increments
  its version and retains who revoked it and when. The version change and audit
  event commit together. Revocation does not delete the original approval row.
- `ConsumeAssertion(ctx, use)` locks the current grant, rechecks version,
  revocation, creation and expiration, then inserts the bound identity hash
  atomically. Expiration is also checked against the database clock after lock
  acquisition. Replay/changed/revoked/expired grants return `false, nil`;
  storage/audit failure returns `ErrUnavailable`. The `jti_hash` primary key is
  global: **grant ID and version are metadata, never uniqueness partitions**.
  Core computes this hash from issuer, subject, key ID and JTI. Only the typed
  service may derive that hash from a verified assertion.
- `IsTokenRevoked(ctx, hash)` reads the retained revocation hash.
  `RevokeToken(ctx, hash, actor, at, expiresAt)` is an additional typed adapter
  operation, with a maximum 15 minute token interval. Repeated revocation is
  idempotent. Its caller must separately authorize the current actor and exact
  target; there is no public revocation endpoint or automatic role assignment.
- `ListGrants(ctx, Owner)` is an internal persistence read, bounded to 4096 rows;
  exceeding the bound fails closed instead of silently truncating. It does not
  infer current ownership from historical `ApprovedBy`. The reusable management
  handler resolves the current human owner and filters every result through
  current `OwnerPolicy` **and** `TenantPolicy`. Never expose this adapter method
  directly as an HTTP list endpoint.
- `Record(ctx, Audit)` accepts fixed operation/reason/scope codes and bounded
  verified metadata. It rejects raw error strings, tokens, PEM and email-like
  owner IDs. Mutation methods also write distinct committed events inside their
  own transactions, so failure of a later service-level audit cannot hide an
  already committed grant mutation.

All public database errors collapse to `ErrUnavailable`, `ErrConflict` or
`ErrDenied`; DSNs, SQL errors, PEM and tokens are not returned. There are no
automatic retries. A commit error can have an uncertain outcome: read back
current durable state before any explicit recovery, and never replay a consumed
assertion or retry a stale version automatically.

## Explicit, unapplied SQL and host adoption

[`schema.sql`](../../agentidentity/postgres/schema.sql) is a **new, unapplied
host prerequisite**, not a constructor migration or a currently adopted host
schema version. It creates only the four service-identity tables, their indexes
and immutable-record triggers. Foreign keys reference only these new tables;
there is no assumed host users/tenant/factor schema. SQL enforces positive
versions/tenant IDs, bounded finite grant/assertion/token intervals and
consistent revocation metadata. Grant lifetime uses elapsed 720 hours, avoiding
session timezone/DST dependence. Audit, assertion-consume and token-revocation
rows reject updates, deletes and truncation. Expired hashes remain retained;
pruning them would reopen identity reuse. History retention/archival and an
outbox delivery cursor are separate approved host work, not automatic cleanup.

Adoption requires a separately reviewed host migration that selects one trusted
shared namespace and runs this SQL in a caller-owned transaction with a reviewed
local `search_path`. The host must assign a new schema version and exact matched
image/continuity admission, preserve existing content/auth baselines, fence all
writers and refuse old writers after adoption. The current CMS schema10→11
admission does not authorize this schema, nor does the proposed CMS10→12 history
sequence. Do not renumber or edit released migrations to make these tables fit.
The complete combined host target/admission is still an integration gate.

An operator migration role owns the tables/triggers. A separate runtime role
needs namespace `USAGE`; grant `SELECT`/`INSERT` plus update of only
`version`, `revoked`, `revoked_by`, `revoked_at`; assertion/revocation
`SELECT`/`INSERT`; audit `INSERT`; and identity-sequence `USAGE`. Approved audit
readback/outbox consumers additionally need audit `SELECT`. The runtime role
must not own tables, disable triggers or obtain `DELETE`, `TRUNCATE`, schema
creation or human/factor/bootstrap access. If a later permission/key rotation
API is added, it must atomically increment the grant version and append an audit
event. No such mutation API is implemented here.

SQL privileges, any database credential configuration, managed issuer adoption,
workload key custody and per-tenant owner activation remain explicit approval
and integration prerequisites. Use supported host/wfctl configuration and secret
references where available; do not paste personal credentials between sites.
This source change applies no migration, creates no real credential or grant,
and does not change a live or staging host.

## Verification boundary

Source tests prove constructor non-I/O, namespace rejection, bounded metadata
and redaction under a driver that produces synthetic secret-bearing errors.
Real PostgreSQL tests run only when `AGENTIDENTITY_TEST_DATABASE_URL` is explicitly
set. The accepted URI must name numeric loopback, an explicit port/password,
`/agentidentity_test` and only `sslmode=disable`; inherited personal libpq
profiles are disabled and passfile resolution points to a nonexistent fixture
path. Each test creates a random owned schema, adopts SQL only there and drops
only that schema. An absent variable skips; a configured bad/unavailable database
**fails**. CI supplies PostgreSQL 17 and a synthetic ephemeral test password.

```sh
GOWORK=off go test -race ./agentidentity/...
GOWORK=off go vet ./agentidentity/...
```

The PG fixtures cover two independent tenant positives; owner list/resource
cross-negatives; 24 concurrent replay contenders across tenant grants;
actual service exchange/authorization over durable storage using a synthetic
in-memory signer (including cross-tenant replay and token/grant revocation);
global replay after a grant-version change; fresh connection-pool persistence
of public keys, revocation and replay; database-clock expiration; revoke/consume
serialization; SQL lifetime/metadata constraints; retained-row immutability;
and audit-failure rollback of create, revoke, consume and token revocation.
They use synthetic owners and public keys, not human login/factor credentials.

CI/package proof does not replace fresh mounted host API, saved CMS history and
browser proof. A **separate fresh human owner passkey/TOTP continuity ceremony**
is required after host adoption. Agent CMS/frontend QA cannot supply that proof;
its absence remains a blocker even if package/PG/browser fixtures pass.
