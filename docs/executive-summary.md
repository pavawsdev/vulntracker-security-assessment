# VulnTracker Security Assessment — Executive Summary

## The bottom line
VulnTracker holds some of our most sensitive data: the list of security weaknesses
our customers have not yet fixed, along with the accounts that protect it. When this
review began, that information was not adequately protected. A single ordinary user
account — or anyone who obtained a copy of the application's source code — could have
read every customer's unresolved security issues and walked away with their login
credentials. For a product whose entire value is trust, this was a serious exposure.

That core exposure has now been closed. The work is not finished, but the service is
in a materially stronger position than it was.

## Before and after
**Before:** The application trusted its users far more than it should have. People
could reach data that did not belong to them, the key that proves who a user is was
written into the code for anyone to copy, and the system quietly recorded users'
passwords in its own logs. Several of these weaknesses required little skill to exploit.

**After:** Users can now see only their own data. The identity key is held separately
and supplied to the service only when it runs, never written in the code. Passwords are
no longer logged. The most dangerous data-exposure flaws have been fixed, and each fix is
backed by an automated test so it cannot silently return. The service now also ships in a
locked-down, hardened form ready for a production environment.

## Top 3 residual risks
1. **The notification component still trusts its network.** A connected helper service
   assumes everything that can reach it is friendly. We reduced the exposure by fencing
   off its network access, but it should be given its own authentication. It was left for
   a follow-up because a proper fix is a design change, and this review was scoped to the
   main application.

2. **Previously exposed secrets must be retired.** The old identity key and credentials
   were removed from the current code, but they still exist in the project's history.
   Until they are formally replaced with fresh values at deployment, they should be
   considered known to outsiders. This is a quick operational task, not a code change.

3. **Third-party building blocks go out of date continuously.** The software is assembled
   from many external components, and new weaknesses in them are discovered every week. We
   updated the most security-sensitive ones, but a one-time update is stale within weeks,
   and a few have no corrected version available yet. This needs an ongoing process, not a
   single effort.

## Recommended next steps
- **Rotate the exposed secrets now.** Lowest effort, removes a known hole immediately.
- **Automate dependency updates and block risky releases.** Keep the external components
  current automatically, and stop any build that introduces a serious new weakness.
- **Give the notification service its own authentication** and reduce how much the system
  reveals about itself when something goes wrong.
- **Plan the move off the prototype database** to a managed one, so the service can scale
  and retain data reliably in production.

With the critical exposures closed and these steps on the roadmap, VulnTracker can be
operated in production with a level of risk appropriate to the sensitivity of the data
it holds.
