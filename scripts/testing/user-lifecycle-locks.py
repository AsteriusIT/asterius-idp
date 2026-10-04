#!/usr/bin/env python3
"""Owned PostgreSQL lock-order smoke; structural SQL, not a Rust adapter test.

Requires explicit PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD for an approved
scratch PostgreSQL instance. Creates and drops only a nonce schema. The CI Rust
regression separately exercises the actual PgUserRepository and signing fence.
"""
import json
import os
import subprocess
import time
import uuid

for key in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER"):
    if not os.environ.get(key):
        raise SystemExit(f"explicit {key} required")
schema = "lifecycle_smoke_" + uuid.uuid4().hex
processes = []


def sql(statement):
    return subprocess.check_output(
        ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", statement],
        text=True,
    ).strip()


def session(name):
    env = dict(os.environ, PGAPPNAME=schema + name)
    process = subprocess.Popen(
        ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    processes.append(process)
    send(process, f"set search_path={schema}; set statement_timeout='5s';")
    return process


def send(process, statement):
    process.stdin.write(statement + "\n\\echo DONE\n")
    process.stdin.flush()


def complete(process):
    lines = []
    while True:
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("owned SQL connection failed: " + process.stderr.read())
        if line.strip() == "DONE":
            return lines
        lines.append(line.strip())


def waiting(name):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if sql(f"select exists(select 1 from pg_stat_activity where application_name='{schema}{name}' and wait_event_type='Lock')") == "t":
            return
        time.sleep(0.02)
    raise RuntimeError("expected real PostgreSQL lock wait")


try:
    sql(f"create schema {schema}; create table {schema}.tenants(tenant_id text primary key); create table {schema}.users(tenant_id text,user_id int,status text); insert into {schema}.tenants values('owned'); insert into {schema}.users values('owned',1,'active');")
    reader, writer = session("reader"), session("writer")
    complete(reader)
    complete(writer)
    send(reader, "begin; select tenant_id from tenants where tenant_id='owned' for share;")
    complete(reader)
    send(writer, "begin; select tenant_id from tenants where tenant_id='owned' for no key update; select user_id from users where user_id=1 for update; update users set status='disabled' where user_id=1; commit;")
    waiting("writer")
    assert sql(f"begin; select status from {schema}.users where user_id=1 for share nowait; rollback;") == "active"
    send(reader, "commit;")
    complete(reader)
    complete(writer)
    assert sql(f"select status from {schema}.users where user_id=1") == "disabled"
    send(writer, "begin; select tenant_id from tenants where tenant_id='owned' for no key update; update users set status='active' where user_id=1;")
    complete(writer)
    send(reader, "begin; select tenant_id from tenants where tenant_id='owned' for share; select status from users where user_id=1 for share; commit;")
    waiting("reader")
    send(writer, "commit;")
    complete(writer)
    assert "active" in complete(reader)
    print(json.dumps({"signer_first_user_unlocked": True, "disable_committed": True, "writer_first_reader_waits": True, "post_wait_current_status": True, "scope": "owned minimal SQL lock-order smoke; actual adapters CI-only"}))
finally:
    for process in processes:
        process.stdin.close()
        try:
            process.wait(timeout=7)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=3)
    sql(f"drop schema if exists {schema} cascade;")
