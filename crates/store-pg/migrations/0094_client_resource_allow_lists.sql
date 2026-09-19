-- Materialise the audience clients previously inherited implicitly.
--
-- Before the admin resource editor, an empty clients.resources array meant
-- "use tenants.default_resource" at issuance. The editor gives an empty array
-- the safer and explicit meaning "this client may request no resource". Copy
-- the old effective value into existing rows so the migration does not turn
-- working integrations off merely by changing how the same policy is stored.
--
-- Only copy a registered audience. A tenant whose default is not in its
-- registry already receives invalid_target, and migration must not turn an
-- unusable implicit default into an apparently authorized one.
update clients as client
   set resources = array[tenant.default_resource]
  from tenants as tenant
 where client.tenant_id = tenant.tenant_id
   and cardinality(client.resources) = 0
   and exists (
       select 1
         from resource_servers as server
        where server.tenant_id = tenant.tenant_id
          and server.identifier = tenant.default_resource
   );
