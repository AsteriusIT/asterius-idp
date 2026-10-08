-- Only disposable Message Signing clients opt into explicit ES256 JAR/JARM.
\set ON_ERROR_STOP on
update clients
   set request_object_signing_alg = 'ES256',
       authorization_signed_response_alg = 'ES256',
       response_modes = array['jwt']
 where tenant_id = :'tenant'
   and client_id in ('conformance-client-1', 'conformance-client-2');
