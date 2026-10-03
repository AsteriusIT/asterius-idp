#!/usr/bin/env python3
"""Real Asterius DPoP controls; no enterprise-client success is inferred."""
import json
import os
import secrets
import subprocess
import urllib.parse
from dpop_fixture import FixtureClient


def run():
    issuer = os.environ["ASTERIUS_SCIM_ISSUER"]
    args = (os.environ["ASTERIUS_SCIM_SIGNING_KEY_FILE"], os.environ["ASTERIUS_SCIM_SIGNING_KEY_ID"], os.environ["ASTERIUS_SCIM_CA_FILE"])
    c = FixtureClient(issuer, os.environ["ASTERIUS_SCIM_CLIENT_ID"], *args)
    other = FixtureClient(issuer, os.environ["ASTERIUS_SCIM_OTHER_CLIENT_ID"], *args)
    base = issuer + "/admin/api/v1/scim/v2"
    records = []
    def req(label, method, path, wanted, body=None, etag=None, client=c, bearer=False):
        status, headers, value = client.request(method, base + path, body, {"If-Match": etag} if etag else {}, bearer=bearer)
        records.append({"case": label, "status": status})
        if status not in wanted:
            raise RuntimeError(f"{label}: expected {wanted}, received {status}")
        return headers, value
    nonce = secrets.token_hex(8)
    user_id = group_id = None
    try:
        for route in ["ServiceProviderConfig", "Schemas", "ResourceTypes"]:
            req("DPoP discovery " + route, "GET", "/" + route, [200])
        req("same token Bearer refused", "GET", "/Users", [401], bearer=True)
        cross = os.environ["ASTERIUS_SCIM_CROSS_TENANT_ISSUER"] + "/admin/api/v1/scim/v2/Users"
        status, _, _ = c.request("POST", cross, {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "cross-tenant-"+nonce})
        records.append({"case": "cross-tenant creation refused", "status": status})
        if status not in (401, 403):
            raise RuntimeError("cross-tenant credential isolation failed")
        body = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "entra-probe-" + nonce,
                "externalId": "entra-" + nonce, "active": True, "emails": [{"value": nonce + "@example.invalid", "type": "work"}]}
        h, user = req("create user", "POST", "/Users", [201], body)
        user_id, etag = user["id"], h["ETag"]
        req("duplicate user retry refused", "POST", "/Users", [409], body)
        req("exact userName filter", "GET", "/Users?" + urllib.parse.urlencode({"filter": 'userName eq "'+body["userName"]+'"'}), [200])
        req("externalId matching unsupported", "GET", "/Users?" + urllib.parse.urlencode({"filter": 'externalId eq "'+body["externalId"]+'"'}), [400])
        patch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "Replace", "path": "active", "value": False}]}
        req("native shape without If-Match refused", "PATCH", "/Users/"+user_id, [428], patch)
        h, user = req("disable user with ETag", "PATCH", "/Users/"+user_id, [200], patch, etag)
        new_etag = h["ETag"]
        req("stale retry refused", "PATCH", "/Users/"+user_id, [412], patch, etag)
        patch["Operations"][0]["value"] = True
        h, user = req("reactivate provisioning-disabled user", "PATCH", "/Users/"+user_id, [200], patch, new_etag)
        etag = h["ETag"]
        subprocess.run([os.environ["ASTERIUS_SCIM_LOCK_COMMAND"], user_id], check=True, capture_output=True)
        h, locked = req("read security-locked user", "GET", "/Users/"+user_id, [200])
        if locked["active"] is not False:
            raise RuntimeError("security-locked SCIM user must be inactive")
        etag = h["ETag"]
        req("security lock cannot be cleared by SCIM", "PATCH", "/Users/"+user_id, [409], patch, etag)
        # Preserve the security lock through disable; later activation must still fail.
        patch["Operations"][0]["value"] = False
        h, locked = req("disable locked user", "PATCH", "/Users/"+user_id, [200], patch, etag)
        if locked["active"] is not False:
            raise RuntimeError("disabled security-locked SCIM user must remain inactive")
        etag = h["ETag"]
        patch["Operations"][0]["value"] = True
        req("disable then activate cannot bypass security lock", "PATCH", "/Users/"+user_id, [409], patch, etag)
        patch["Operations"][0]["value"] = "False"
        req("legacy string active unsupported", "PATCH", "/Users/"+user_id, [400], patch, etag)
        extended = {**body, "userName": "entra-extension-"+nonce, "name": {"givenName": "Fixture"}}
        req("default name mapping unsupported", "POST", "/Users", [400], extended)
        groupbody = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "entra-group-"+nonce,
                     "externalId": "entra-group-"+nonce, "members": [{"value": user_id}]}
        gh, group = req("create group with member", "POST", "/Groups", [201], groupbody)
        group_id = group["id"]
        req("foreign controller cannot read group", "GET", "/Groups/"+group_id, [404], client=other)
        req("excludedAttributes unsupported", "GET", "/Groups?excludedAttributes=members", [400])
        memberpatch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": 'members[value eq "'+user_id+'"]'}]}
        gh, group = req("modern member remove with ETag", "PATCH", "/Groups/"+group_id, [200], memberpatch, gh["ETag"])
        req("delete group", "DELETE", "/Groups/"+group_id, [204], etag=gh["ETag"])
        group_id = None
        req("delete user", "DELETE", "/Users/"+user_id, [204], etag=etag)
        req("deleted user invisible", "GET", "/Users/"+user_id, [404])
        user_id = None
    finally:
        for collection, identity in [("Groups", group_id), ("Users", user_id)]:
            if identity:
                status, headers, _ = c.request("GET", base+"/"+collection+"/"+identity)
                if status == 200:
                    deleted, _, _ = c.request("DELETE", base+"/"+collection+"/"+identity, headers={"If-Match": headers["ETag"]})
                    if deleted != 204:
                        raise RuntimeError("owned SCIM control cleanup failed")
    print(json.dumps({"profile": "Asterius scoped DPoP control; not native Entra provisioning", "cases": records}, indent=2))


if __name__ == "__main__":
    run()
