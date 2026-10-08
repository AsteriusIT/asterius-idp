#!/usr/bin/env python3
"""Native SSFgo push worker → approved TLS relay → real Asterius receiver."""
import argparse,hashlib,json,re,secrets,subprocess,time,urllib.request,urllib.error,urllib.parse,uuid
from pathlib import Path
from lifecycle import Admin


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['manifest','automation','bearer-file','database-container','native-binary']:p.add_argument('--'+name,required=True)
    args=p.parse_args()
    manifest=json.loads(Path(args.manifest).read_text())
    config=json.loads(Path(args.automation).read_text())
    assert manifest['issuer']=='https://localhost:18444/t/e2e' and manifest['database']==config['database'] and re.fullmatch(r'ast_product_[a-f0-9]{32}',config['database'])
    peer='https://desktop-cpbptqn-1.tailacbb15.ts.net:10000/ssf-push-peer'
    endpoint='https://desktop-cpbptqn-1.tailacbb15.ts.net:10000/asterius-ssf/receiver'
    assert re.fullmatch(r'asterius-[A-Za-z0-9_.-]+',args.database_container)
    assert Path(args.bearer_file).stat().st_mode & 0o077 == 0
    bearer=Path(args.bearer_file).read_text().strip()
    admin=Admin(config['issuer'],config['clientId'],config['keyFile'],config['keyId'],config['caFile'])
    q=lambda x:"'"+x.replace("'","''")+"'"
    def sql(s):
        r=subprocess.run(['docker','exec','-i',args.database_container,'psql','-U','asterius','-d',config['database'],'-At','-v','ON_ERROR_STOP=1'],input=s,text=True,capture_output=True)
        if r.returncode:raise RuntimeError('Owned SQL control refused')
        return r.stdout.strip()
    def native(method,path,body=None,control=False):
        request=urllib.request.Request('http://127.0.0.1:'+('19486' if control else '19485')+path,None if body is None else json.dumps(body).encode(),{'Authorization':'Bearer '+bearer,'Content-Type':'application/json'},method=method)
        try:r=urllib.request.urlopen(request,timeout=20)
        except urllib.error.HTTPError as e:r=e
        data=r.read(65537);assert len(data)<=65536
        return r.status,json.loads(data) if data else None
    code,meta=native('GET','/.well-known/ssf-configuration/ssf-push-peer')
    assert code==200 and meta['issuer']==peer and meta['delivery_methods_supported']==['urn:ietf:rfc:8935']
    assert sql("select count(*) from clients where tenant_id='e2e' and client_id="+q(peer))=='0'
    user,session,subject=str(uuid.uuid4()),str(uuid.uuid4()),'owned-native-push-'+secrets.token_hex(16)
    sql("begin; insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,jwks_uri,dpop_bound_access_tokens) values('e2e',"+q(peer)+",'Owned native push','private_key_jwt',array['client_credentials'],'{}',array['ssf.receive'],"+q(meta['jwks_uri'])+",true); insert into users(tenant_id,user_id,username) values('e2e',"+q(user)+','+q(subject)+"); insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at) values('e2e',"+q(session)+','+q(session)+','+q(user)+",now(),now()+interval '1 hour',now()+interval '1 hour'); commit;")
    stream=None
    try:
        code,_,_=admin.request('PUT',config['issuer']+'/admin/api/v1/ssf/receiver/subjects',{'peer_client_id':peer,'subject':{'format':'iss_sub','iss':peer,'sub':subject},'user_id':user},{'Content-Type':'application/json','Idempotency-Key':str(uuid.uuid4())});assert code==200
        path=urllib.parse.urlsplit(meta['configuration_endpoint']).path
        code,stream=native('POST',path,{'events_requested':['https://schemas.openid.net/secevent/caep/event-type/session-revoked'],'delivery':{'method':'urn:ietf:rfc:8935','endpoint_url':endpoint}});assert code==201
        assert native('POST','/emit-session-revoked',{'subject':subject},True)[0]==204
        for _ in range(60):
            receipts=native('GET','/delivery-receipts',control=True)[1]
            if any(x['outcome']=='delivered' for x in receipts):break
            time.sleep(1)
        assert any(x['outcome']=='delivered' for x in receipts), 'Native push failed: '+str(receipts)
        assert sql("select count(*) from sessions where tenant_id='e2e' and session_id="+q(session)+' and revoked_at is not null')=='1'
        assert sql("select count(*) from ssf_receiver_events where tenant_id='e2e' and peer_client_id="+q(peer))=='1'
        print(json.dumps({'status':'pass','profile':'SSF1Final/operator-bearer/ALL/ES256/native-push','libraryRevision':'ce2353e22367c276f8dada1dbf22ec9939a255b1','independentBinarySha256':hashlib.sha256(Path(args.native_binary).read_bytes()).hexdigest(),'runtimeRevision':manifest['runtime_revision'],'runtimeBinarySha256':manifest['binary_sha256'],'checks':[{'case':'real authenticated explicit subject mapping','status':200},{'case':'native push-only stream creation exact HTTPS endpoint','status':201},{'case':'native SSFgo Run worker verified HTTPS delivery','nativeReceipts':receipts},{'case':'actual session revoked with exactly one receiver inbox row','pass':True}],'formalCAEPConformance':False,'limits':['Owned session explicitly seeded; native library, not Python, generates/signs/delivers SET.']},indent=2))
    finally:
        if stream:assert native('DELETE',path+'?'+urllib.parse.urlencode({'stream_id':stream['stream_id']}))[0]==204
        sql("delete from users where tenant_id='e2e' and user_id="+q(user)+"; delete from clients where tenant_id='e2e' and client_id="+q(peer)+';')

if __name__=='__main__':main()
