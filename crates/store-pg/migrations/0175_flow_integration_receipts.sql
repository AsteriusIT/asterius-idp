-- Public registration revision: detects external credential-only edits without
-- storing a secret, credential hash or envelope in diagram/provenance JSON.
alter table flow_resource_links add column resource_revision text;

-- Origin belongs to the local configured relationship, survives uncertain POSTs,
-- and is copied to the established record by the same transaction as setup.
alter table ssf_receiver_upstream_setup_intents
    add column origin_flow uuid,
    add column origin_node text,
    add constraint upstream_setup_flow_origin foreign key (tenant_id, origin_flow, origin_node)
        references flow_resource_links (tenant_id, flow_id, node_id),
    add constraint upstream_setup_origin_pair check ((origin_flow is null) = (origin_node is null));
alter table ssf_receiver_upstream_streams
    add column origin_flow uuid,
    add column origin_node text,
    add constraint upstream_stream_flow_origin foreign key (tenant_id, origin_flow, origin_node)
        references flow_resource_links (tenant_id, flow_id, node_id),
    add constraint upstream_stream_origin_pair check ((origin_flow is null) = (origin_node is null));
