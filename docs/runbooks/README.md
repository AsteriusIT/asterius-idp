# Runbooks

Operational procedures for a running deployment. Each one describes the system
**as it is**, not as it is meant to become: where a step is manual, it says so,
and every command in them has been run against the binary that ships.

That rule is the point of this directory. A runbook is read at 3am by somebody
who then discovers the command does not exist, so a procedure nobody has
verified is worse than an empty page — the empty page at least does not send an
operator down a path that ends in an unknown subcommand.

| Runbook | When you reach for it |
| --- | --- |
| [`upgrade.md`](upgrade.md) | Moving a deployment from one build to the next: what runs the migrations, what a multi-replica rollout does to the replicas that have not restarted yet, and what "rollback" can and cannot mean. |
| [`kek-rotation.md`](kek-rotation.md) | Replacing the key-encryption key, online or offline; rolling a rotation back; destroying one compromised signing key. |
| [`backup-restore.md`](backup-restore.md) | What has to be backed up, why the database and the KEK must not go to the same place, and how to restore both. |

Related reading that is not a runbook: [`../configuration.md`](../configuration.md)
(every key, generated from the schema), [`../threat-model.md`](../threat-model.md)
(what these procedures defend and what they leave standing), and
[`../../deploy/README.md`](../../deploy/README.md) (the shape of a deployment).
