# Where work runs

The runtime location determines who can see plaintext and which protections
GaugeDesk can enforce.

| Mode | Use today | Who can see required plaintext |
| --- | --- | --- |
| Your computer | Available | You and the model provider |
| Your other devices | Available in the stated self-federation scope | The target device owner and model provider |
| Another team's system | Built; general managed service is not established | The target operator and model provider |
| GaugeWright-managed private host | Limited managed use | GaugeWright and model provider, unless independent verification removes GaugeWright |
| Independently verified host | Built, not generally available | The verified workload and model provider |
| Website agent | Production proof; not general self-service | GaugeWright's hosted runtime and model provider |

## Your computer

GaugeDesk stores and runs project orchestration on your computer. The selected
model provider performs inference and receives the prompt and allowed context.

Linux and macOS have the current operating-system isolation for agent
instructions. Windows does not have the same isolation.

## Work on another device or team

GaugeDesk can send encrypted content through a relay. The relay cannot read the
content. The receiving system performs its own permission checks before use.

Self-federation is available in its stated scope. A general managed cross-team
service is not established.

## Managed and independently verified hosts

A managed host places GaugeWright in the trust boundary. An independently
verified host can prove which approved workload is running before it receives
decryption keys.

This verified-host path is built but not generally available. It does not hide
plaintext from the model provider.

## Website agents

Website sessions run in a hosted, session-specific runtime. The author's
computer is not in the serving path. GaugeWright has a live production proof,
but general self-service availability and an uptime SLA are not established.

See [Product status](../reference/status.md) for the current scope.
