"""Optional viewer controls on the existing controlled HTTPS task fixture.
Only sanitized checks reach its evidence. Never print bearer credentials.
"""
import json
import uuid
class ViewerFixture:
    def __init__(self, admin, issuer, sql, literal, binding, owner, agent, agent_token):
        self.admin=admin;self.issuer=issuer;self.sql=sql;self.literal=literal
        self.binding=binding;self.owner=owner;self.agent=agent;self.agent_token=agent_token
        self.foreign=str(uuid.uuid4())
        tenant=str(uuid.uuid4())
        # A foreign task with immutable provenance but removed live references.
        # It must neither appear in the routed tenant nor resolve by guessed UUID.
        sql(f"insert into tenants(tenant_id,issuer,display_name,default_resource) values({literal(tenant)},{literal(issuer+'/foreign')},'Foreign fixture',{literal(issuer+'/admin/api/v1')}); insert into agent_tasks(tenant_id,task_id,root_grant_id,owner_user_id,initiating_client_id,permissions,label,approved_at,expires_at) select {literal(tenant)},{literal(self.foreign)},{literal(str(uuid.uuid4()))},owner_user_id,initiating_client_id,permissions,'foreign-private-label',now(),now()+interval '5 minutes' from agent_tasks where tenant_id='tasks' and task_id={literal(binding['task_id'])};")
    def get(self,path):
        status,headers,body=self.admin.request('GET',self.issuer+'/admin/api/v1/'+path)
        return status,headers,body
    def before(self):
        self.agent.token=self.agent_token
        assert self.agent.request('GET',self.issuer+'/admin/api/v1/agents/tasks')[0]==403,'task approval does not grant viewer read scope'
        status,headers,page=self.get('agents/tasks?limit=1')
        assert status==200 and 'no-store' in headers['cache-control'].lower(),'bounded no-store task list'
        assert len(page['items'])==1 and page['next_cursor'],'list cursor bounds'
        next_page=self.get('agents/tasks?limit=1&cursor='+page['next_cursor'])[2]
        assert len(next_page['items'])==1 and next_page['items'][0]['task_id']!=page['items'][0]['task_id'],'keyset page distinct'
        assert self.get('agents/tasks/'+self.foreign)[0]==404,'cross-tenant guessed task UUID refusal'
        all_tasks=self.get('agents/tasks?limit=50')[2]
        assert self.foreign not in json.dumps(all_tasks) and 'foreign-private-label' not in json.dumps(all_tasks),'no cross-tenant metadata'
        for query in ['limit=0','limit=51','limit=25&limit=25','token=secret','owner=bad']:
            assert self.get('agents/tasks?'+query)[0]==400,'closed bounded parser'
        status,headers,snapshot=self.get('agents/tasks/'+self.binding['task_id']+'?limit=1')
        assert status==200 and len(snapshot['lineage'])==1 and snapshot['next_cursor'],'bounded snapshot lineage'
        assert snapshot['conditional_decision']=='not_evaluated','viewer does not manufacture conditional decision'
        assert snapshot['task']['owner_user_id']==self.owner and snapshot['task']['approval_revision']==self.binding['approval_revision'],'immutable owner/revision binding'
        assert snapshot['task']['state']=='active' and 0<snapshot['maximum_new_token_ttl_seconds']<=120,'current lifecycle and clipped lifetime'
        assert snapshot['current_issuance_ceiling']['scopes']==['admin.scim:read'],'approved scope intersection'
        original_scopes=self.sql("select to_json(scopes)::text from clients where tenant_id='tasks' and client_id="+self.literal(self.agent.client_id),True)
        try:
            self.sql("update clients set scopes=array[]::text[] where tenant_id='tasks' and client_id="+self.literal(self.agent.client_id))
            narrowed=self.get('agents/tasks/'+self.binding['task_id'])[2]
            assert not narrowed['current_issuance_ceiling']['scopes'],'current client restriction observed independently'
            assert narrowed['approved_ceiling']['scopes']==['admin.scim:read'],'historical approval is not rewritten by current restriction'
        finally:
            self.sql("update clients set scopes=array(select jsonb_array_elements_text("+self.literal(original_scopes)+"::jsonb)) where tenant_id='tasks' and client_id="+self.literal(self.agent.client_id))

        assert all(len(node['ancestry'])<=10 and node['ancestry'][0]==self.binding['root_grant_id'] for node in snapshot['lineage']),'bounded root-first lineage'
        rendered=json.dumps(snapshot)
        for private in ['controlled-owner','foreign-owner','email','password','jti','access_token','refresh_token']:
            assert private not in rendered,'viewer privacy fields'
        assert self.get('agents/tasks/'+self.binding['task_id']+'?owner='+self.owner)[0]==400,'snapshot cannot accept hidden owner selector'
    def after_intermediate(self,grant):
        page=self.get('agents/tasks/'+self.binding['task_id']+'?limit=50')[2]
        node=next(node for node in page['lineage'] if node['grant_id']==grant)
        assert node['state']=='withdrawn' and not node['current_issuance_ceiling']['scopes'],'intermediate current authority empty'
        assert page['task']['state']=='active','intermediate does not terminalize task'
        assert any(node['state']=='active' for node in page['lineage']),'same-task sibling still represented live'
    def after_root(self):
        snapshot=self.get('agents/tasks/'+self.binding['task_id']+'?limit=50')[2]
        assert snapshot['task']['state']=='withdrawn' and snapshot['maximum_new_token_ttl_seconds']==0,'terminal current task'
        assert not snapshot['current_issuance_ceiling']['scopes'] and not snapshot['current_grant_types'],'terminal effective ceiling empty'
        assert all(not node['current_issuance_ceiling']['scopes'] for node in snapshot['lineage']),'descendant current authority empty'
        timeline=self.get('audit/events?task='+self.binding['task_id'])[2]
        assert timeline['items'],'recorded timeline independent of current authority'
        assert all(row.get('detail',{}).get('task_id')==self.binding['task_id'] for row in timeline['items']),'exact task recorded event filtering'
