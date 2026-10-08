-- The exact historical0173 is retained for databases that already applied it.
-- Install the corrected history schema without inventing old values, drawing
-- client IDs, revoking authority, or updating migration/audit history. Fresh
-- databases with corrected0173 already have this schema: preserve their actual
-- captured pre-cutover values and existing immutable triggers.
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM clients
        WHERE client_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          AND client_id NOT LIKE 'https://%'
    ) THEN
        RAISE EXCEPTION 'UUID history schema parity requires an already completed client ID migration; no terminal cutover is authorized here';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION client_uuid_lookup_history_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE column_name text;
BEGIN
    FOREACH column_name IN ARRAY tg_argv LOOP
        IF (tg_op='INSERT' AND to_jsonb(new)->column_name IS DISTINCT FROM 'null'::jsonb)
           OR (tg_op='UPDATE' AND to_jsonb(new)->column_name IS DISTINCT FROM to_jsonb(old)->column_name) THEN
            RAISE EXCEPTION 'UUID client cutover lookup history is immutable' USING errcode='23514';
        END IF;
    END LOOP;
    RETURN new;
END $$;

DO $$ DECLARE item record; snapshot_name text; actual_type text; BEGIN
    FOR item IN
        SELECT c.table_schema,c.table_name,c.column_name
        FROM information_schema.columns c
        WHERE c.table_schema=current_schema() AND c.data_type='text'
          AND (c.column_name LIKE '%client_id' OR c.column_name LIKE '%client_reference')
          AND c.table_name NOT IN ('audit_events','client_id_migrations','oidc_identity_providers','oidc_upstream_pending',
              'agent_tasks','temporary_entitlements','temporary_entitlement_requests','temporary_kubernetes_bindings')
          AND EXISTS (SELECT 1 FROM information_schema.columns t WHERE t.table_schema=c.table_schema
              AND t.table_name=c.table_name AND t.column_name='tenant_id')
    LOOP
        snapshot_name:=item.column_name || '_before_uuid_cutover';
        EXECUTE format('ALTER TABLE %I.%I ADD COLUMN IF NOT EXISTS %I text',item.table_schema,item.table_name,snapshot_name);
        SELECT data_type INTO actual_type FROM information_schema.columns
          WHERE table_schema=item.table_schema AND table_name=item.table_name AND column_name=snapshot_name;
        IF actual_type IS DISTINCT FROM 'text' THEN
            RAISE EXCEPTION 'UUID lookup history schema has incompatible column type';
        END IF;
    END LOOP;
END $$;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS authority_revision_before_uuid_cutover uuid;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS subject_before_uuid_cutover text;

DO $$ DECLARE item record; BEGIN
    IF (SELECT data_type FROM information_schema.columns WHERE table_schema=current_schema()
        AND table_name='grants' AND column_name='authority_revision_before_uuid_cutover') IS DISTINCT FROM 'uuid'
       OR (SELECT data_type FROM information_schema.columns WHERE table_schema=current_schema()
        AND table_name='grants' AND column_name='subject_before_uuid_cutover') IS DISTINCT FROM 'text' THEN
        RAISE EXCEPTION 'UUID grant history schema has incompatible column type';
    END IF;
    FOR item IN
        SELECT table_schema,table_name,string_agg(quote_literal(column_name),',' ORDER BY ordinal_position) AS args,
               count(*) AS argument_count,
               decode(string_agg(encode(convert_to(column_name,'UTF8'),'hex') || '00','' ORDER BY ordinal_position),'hex') AS encoded_arguments
        FROM information_schema.columns
        WHERE table_schema=current_schema() AND column_name LIKE '%_before_uuid_cutover'
        GROUP BY table_schema,table_name
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger
            WHERE tgrelid=format('%I.%I',item.table_schema,item.table_name)::regclass
              AND tgname='client_uuid_lookup_history_immutable' AND NOT tgisinternal) THEN
            EXECUTE format('CREATE TRIGGER client_uuid_lookup_history_immutable BEFORE INSERT OR UPDATE ON %I.%I FOR EACH ROW EXECUTE FUNCTION client_uuid_lookup_history_immutable(%s)',
                item.table_schema,item.table_name,item.args);
        ELSIF EXISTS (SELECT 1 FROM pg_trigger
            WHERE tgrelid=format('%I.%I',item.table_schema,item.table_name)::regclass
              AND tgname='client_uuid_lookup_history_immutable'
              AND (tgfoid <> 'client_uuid_lookup_history_immutable()'::regprocedure
                   OR tgnargs <> item.argument_count OR tgargs <> item.encoded_arguments
                   OR tgtype <> 23 OR tgenabled NOT IN ('O','A'))) THEN
            RAISE EXCEPTION 'UUID lookup history trigger has incompatible function or protected columns';
        END IF;
    END LOOP;
END $$;
