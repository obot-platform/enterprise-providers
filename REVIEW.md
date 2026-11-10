# Review notes

- Decide, and document in the provider's README and its Obot docs, how a provider treats an email address its
  identity provider did not mark verified. Allowed E-Mail Domains is the only sign-in gate, so a provider that trusts
  an unverified `email` is only as strong as the attribute behind it. Providers differ on purpose: Keycloak requires
  `email_verified` unless an administrator opts out, while PingFederate, which rarely releases that claim, trusts its
  `email` attribute and tells administrators to map it from a source users cannot edit.
- A provider that records groups at sign-in instead of looking them up (PingFederate) must say how a group removal
  reaches Obot, not only how a user removal does, and how to revoke at once. Its records must only move forward: a
  write from an older token must not undo one from a newer token, whichever session or replica makes it.
- Detect "the refresh returned no new ID token" by comparing the session's ID token before and after the refresh
  (`authcommon.LoadFreshState` returns the previous one), not by the token's age: an age check misfires whenever the
  identity provider's clock drifts from Obot's.
