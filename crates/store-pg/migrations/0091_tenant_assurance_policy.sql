-- Absence/null means the pre-existing deployment ladder. Do not overwrite a
-- configured policy, and never replace unrelated settings document members.
UPDATE tenants
SET settings = jsonb_set(coalesce(settings, '{}'::jsonb), '{options}',
    coalesce(nullif(settings->'options', 'null'::jsonb), '{}'::jsonb) || '{"acr_policy": null}'::jsonb)
WHERE settings->'options'->'acr_policy' IS NULL;
