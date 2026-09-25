-- OpenID Connect Key Binding 1.0: retain the device's requested proof key
-- across the browser approval and single-use token redemption.
alter table device_codes
    add column dpop_jkt text;

alter table device_codes
    add constraint device_codes_dpop_jkt_shape
    check (dpop_jkt is null or dpop_jkt ~ '^[A-Za-z0-9_-]{43}$');
