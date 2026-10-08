#!/usr/bin/env python3
"""Rehearse terminal migration 0173 in a uniquely owned restored-DB schema."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parent.parent
FROZEN = {
    "tasks": "select (to_jsonb(t)-array['client_reference','revoked_at','revocation_reason'])::text from agent_tasks t order by task_id",
    "definitions": "select (to_jsonb(t)-array['client_reference','role_reference','enabled','revision'])::text from temporary_entitlements t order by entitlement_id",
    "requests": "select (to_jsonb(t)-array['status','decided_at','decided_by','decision_key'])::text from temporary_entitlement_requests t order by request_id",
    "kubernetes": "select (to_jsonb(t)-array['controller_reference','cluster_client_reference','enabled','revision'])::text from temporary_kubernetes_bindings t order by entitlement_id",
    "proofs": "select binding::text from managed_device_interaction_proofs order by request_uri_hash",
    "replays": "select payload::text,response::text from temporary_entitlement_replays order by idempotency_key",
    "request_payload": "select parameters::text,interaction_state::text from auth_requests order by request_uri_hash",
    "pinned": "select grant_id,parent_grant_id,parent_authority_revision,actor_chain::text from grants order by grant_id",
    "creation_request": "select initial_spec::text from declarative_creation_keys order by external_key",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restored-database-url", required=True,
                        help="Disposable/restored PostgreSQL only; requires schema creation rights")
    args = parser.parse_args()
    schema = "uuid_cutover_rehearsal_" + uuid.uuid4().hex
    command = ["psql", "-X", "--set=ON_ERROR_STOP=1", "-At",
               "--dbname", args.restored_database_url]

    def execute(sql, expected_error=None):
        result = subprocess.run(command, input=f"set search_path={schema};\n{sql}",
                                text=True, capture_output=True, env=os.environ.copy())
        if expected_error:
            if result.returncode == 0 or expected_error not in result.stderr:
                raise RuntimeError("Expected rejection missing: " + expected_error)
        elif result.returncode:
            raise RuntimeError(result.stderr.replace(args.restored_database_url, "[database]"))
        return result.stdout

    def snapshot():
        return {key: execute(sql) for key, sql in FROZEN.items()}

    created = False
    try:
        execute(f"create schema {schema};")
        created = True
        for path in sorted((ROOT / "crates/store-pg/migrations").glob("*.sql")):
            if int(path.name.split("_")[0]) <= 172:
                execute("begin;\n" + path.read_text() + "\ncommit;")
        execute((ROOT / "scripts/sql/client-id-uuid-terminal-fixture.sql").read_text())
        # Include a declaratively owned application and its original idempotent
        # creation request. Migration must preserve its owner and captured spec.
        execute("""
update declarative_owners set owner='fixture-controller',deletion_protection=true
where tenant_id='cutover' and kind='application' and keys='["old-client"]';
insert into declarative_creation_keys(tenant_id,kind,owner,external_key,keys,initial_spec,initial_protection,incarnation)
select tenant_id,kind,owner,'original-creation',keys,'{"client_id":"old-client"}',true,incarnation
from declarative_owners where tenant_id='cutover' and kind='application' and keys='["old-client"]';
""")
        before = snapshot()
        migration = (ROOT / "crates/store-pg/migrations/0173_uuid_client_ids.sql").read_text()
        execute("begin;\n" + migration + "\ncommit;", "restored-backup rehearsal")
        assert before == snapshot(), "Unapproved attempt changed frozen evidence"
        execute("begin; set local asterius.client_uuid_terminal_cutover='approved';\n"
                + migration + "\nrollback;")
        assert before == snapshot(), "Rollback changed frozen evidence"
        execute("begin; set local asterius.client_uuid_terminal_cutover='approved';\n"
                + migration + "\ncommit;")
        assert before == snapshot(), "Committed cutover rewrote frozen evidence"
        checks = {
            "legacy aliases": "select count(*) from clients where client_id like 'old-%'",
            "live tasks": "select count(*) from agent_tasks where revoked_at is null or client_reference is not null",
            "live descendants": "select count(*) from grants where revoked_at is null",
            "live refresh": "select count(*) from refresh_tokens where revoked_at is null",
            "live entitlements": "select count(*) from temporary_entitlements where enabled or client_reference is not null or role_reference is not null",
            "pending requests": "select count(*) from temporary_entitlement_requests where status='pending'",
            "live activations": "select count(*) from temporary_entitlement_activations where revoked_at is null",
            "live PAR": "select count(*) from auth_requests where expires_at>clock_timestamp()",
            "live JIT bindings": "select count(*) from temporary_kubernetes_bindings where enabled or controller_reference is not null or cluster_client_reference is not null",
        }
        for name, sql in checks.items():
            assert execute(sql).splitlines()[-1] == "0", name
        assert execute("select count(*) from clients where client_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' or client_id='https://client.example/metadata.json'").splitlines()[-1] == "2"
        assert execute("select count(*) from grants where client_id_before_uuid_cutover='old-client' and authority_revision_before_uuid_cutover is not null").splitlines()[-1] == "1"
        execute("update clients set client_id_before_uuid_cutover='forged' where client_id_before_uuid_cutover is not null;", "immutable")
        execute("update temporary_entitlement_requests set client_id='forged';", "immutable")
        execute("update grants set parent_authority_revision=gen_random_uuid() where parent_grant_id is not null;", "immutable")
        print(json.dumps({"schema": schema, "result": "passed",
                          "frozen_groups": len(FROZEN), "terminal_checks": len(checks),
                          "tamper_guards": 3, "live_deployment": False}))
    finally:
        # Delete only this invocation's randomly named schema; retain no fixture
        # accounts, credentials or migration artifacts in the restored database.
        if created:
            execute(f"drop schema {schema} cascade;")


if __name__ == "__main__":
    main()
