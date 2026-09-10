-- The Grant Management action the authorization request carried
-- (Grant Management ID1 §5.2), remembered from the pushed request until the
-- code is redeemed.
--
-- §5.5: "grant_id: … The AS MUST return this parameter if a valid grant
-- management action was requested." The token endpoint is where that response
-- is written, and by then the pushed request is gone and the code is the only
-- thing tying the two halves of the flow together — so the fact travels on the
-- code.
--
-- It is deliberately *not* a column on `grants`. A grant outlives the request
-- that amended it, and a fact stored there would make every later token
-- response for that grant — a refresh months afterwards, which carried no
-- action at all — claim one had been requested.
--
-- Null is "no action was requested", which is what every row written before
-- this column existed means and what an ordinary authorization means today.
-- The check is the same closed list `asterius_oidc::grant_management::Action`
-- parses; §6.1's `query` and `revoke` are actions of the HTTP API and never
-- values of this parameter, so they are not permitted here either.
alter table authorization_codes
    add column grant_management_action text
        check (grant_management_action in ('create', 'merge', 'replace'));
