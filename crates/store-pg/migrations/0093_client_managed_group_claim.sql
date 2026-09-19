-- Group membership is directory data. Existing and new clients receive none
-- unless they explicitly opt in. The claim contains stable group UUID
-- references and is resolved live for the client audience at issuance time.
alter table clients
    add column managed_groups_claim boolean not null default false;
