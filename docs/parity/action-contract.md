# Native action and enforcement contract

Target contract, reconciled 2026-09-11. Exact fail2ban command templates, ActionInfo/private
getters and shell/Python extension ABIs are not product requirements.

## Scope and ownership

Represent the subject (address/network and family), protocol, ports, direction/chain,
interface and enforcement target explicitly where applicable. Separate the owner's policy
identity from the shared kernel object. Releasing one owner's claim must not unban another
owner's protection. Host-wide sets are valid only when the configured scope is host-wide.
Migration must reject unsupported scopes before activation, never broaden them silently.

Retain direct nftables/netlink as the baseline. Existing iptables/ipset tool-backed modes
remain current implementation facts; qualify native replacements or explicitly retire
support before a standalone-runtime claim applies to those modes. Do not silently delete
working coverage during the planning reconciliation.

## Desired state, effects and metadata

Native structured operations carry validated typed fields. Untrusted log text is data and
must never become shell instructions. Retain useful event/time/history metadata with bounded
sizes and explicit missing values; Python object identity, repr, lazy getters and callback
execution are not part of the API.

Persist intent and configuration generation before effects. Track confirmed, failed and
uncertain results; verify kernel state and reconcile after timeout, crash, restart, reload
or partial batch failure. Use idempotent operations when possible and inspect state when
retries could duplicate effects. Permanent and finite bans retain original intent/expiry
through repair. A restore is not automatically a fresh ban notification or recurrence event.

Distinct enforcement targets have distinct outcomes. Optional notifications/providers must
not block or falsely certify enforcement. No arbitrary imported shell/Python action or
ignorecommand is executed during inspection, planning or activation. Report unsupported assets
and provide native mappings only when scope and behavior are actually supported. Optional
connectors require separate product selection, dependency review and real acceptance.

## Acceptance

Test actual kernel state for IPv4/IPv6, service/global scopes, shared owners, expiry, reload,
repair and permission/transport failure on supported backends. Inject controlled interruption
between intent, kernel effect and receipt and verify restart reconciliation. Test malformed
fields, duplicate requests and stale generations. Model tests alone do not certify external
side effects; frozen reference-action probes remain historical implementation evidence.
