// Kubernetes 1.35 structural schemas. Generate checked-in JSON with --write.
import {writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const str = (maxLength=512) => ({type:'string', minLength:1, maxLength});
const name = () => ({...str(63), pattern:'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'});
const https = () => ({...str(2048), pattern:'^https://[^/?# @]+([/?][^# ]*)?$'});
const arr = (items, maxItems=100) => ({type:'array', items, maxItems});
const obj = (properties, required=Object.keys(properties)) => ({type:'object', properties, required});
const immutable = schema => ({...schema, 'x-kubernetes-validations':[{rule:'self == oldSelf', message:'field is immutable; create a new incarnation'}]});
const secretRef = () => obj({name:name(), key:{...str(128),pattern:'^[A-Za-z0-9._-]+$'}});
const common = {
  tenantRef: immutable({...name(), enum:['default']}),
  deletionPolicy: {type:'string', enum:['Retain','Delete'], default:'Retain'},
  deletionProtection: {type:'boolean', default:true},
  importId: immutable({...str(2048), pattern:'^[A-Za-z0-9_-]+$'}),
  adoptionPolicy: {type:'string', enum:['Never','AdoptUnowned'], default:'Never'},
};
const status = obj({
  observedGeneration:{type:'integer', format:'int64', minimum:0},
  observedDeletionProtection:{type:'boolean'},
  remoteId:str(2048), remoteRevision:{...str(64),pattern:'^[0-9a-f]{64}$'},
  conditions: {...arr(obj({type:str(64), status:{type:'string',enum:['True','False','Unknown']},
    reason:str(64), message:{type:'string',maxLength:256},
    observedGeneration:{type:'integer',format:'int64',minimum:0},
    lastTransitionTime:{type:'string',format:'date-time'}}), 8),
    'x-kubernetes-list-type':'map','x-kubernetes-list-map-keys':['type']},
}, []);
const application = obj({...common, clientName:str(256),
  redirectUris:{...arr(https(),16), minItems:1},
  grantTypes:{...arr({type:'string',enum:['authorization_code','refresh_token','client_credentials']},3),minItems:1},
  scopes:arr(str(128)), resources:arr(https()),
  publicJwksSecretRef:secretRef(), jwksUri:https(),
}, ['tenantRef','clientName','redirectUris','grantTypes','scopes','resources']);
application['x-kubernetes-validations'] = [
  {rule:'has(self.publicJwksSecretRef) != has(self.jwksUri)',message:'select exactly one public JWKS source'},
  {rule:'has(oldSelf.importId) == has(self.importId)',message:'import identity is immutable'},
];
const resource = obj({...common, identifier:immutable(https()),
  scopes:{...arr(str(128)),nullable:true},
  defaultTokenLifetimeSeconds:{type:'integer',minimum:1,maximum:86400,nullable:true},
  introspectionClients:arr(str(512)),
}, ['tenantRef','identifier','scopes','defaultTokenLifetimeSeconds','introspectionClients']);
resource['x-kubernetes-validations'] = [{rule:'has(oldSelf.importId) == has(self.importId)',message:'import identity is immutable'}];
// Preserve the existing bounded RuleSet JSON exactly; never prune policy conditions.
// Authoritative RuleSet parsing occurs before remote plan/apply in the controller.
const policy = obj({...common, rulesJson:{...str(65536),description:'Exact existing RuleSet version 1 JSON; parsed by Asterius validators before apply.'}}, ['tenantRef','rulesJson']);
policy['x-kubernetes-validations'] = [{rule:'has(oldSelf.importId) == has(self.importId)',message:'import identity is immutable'}];
const binding = obj({tenantId:immutable({...str(128),pattern:'^[A-Za-z0-9][A-Za-z0-9._-]*$'}),
  issuer:immutable(https()), clientId:immutable(str(512)),
  authenticationKeySecretRef:secretRef(), dpopKeySecretRef:secretRef(),
  issuerCaSecretRef:secretRef(), clusterId:immutable(name()),
}, ['tenantId','issuer','clientId','authenticationKeySecretRef','dpopKeySecretRef','clusterId']);
binding['x-kubernetes-validations']=[{rule:'self.authenticationKeySecretRef.name == oldSelf.authenticationKeySecretRef.name && self.dpopKeySecretRef.name == oldSelf.dpopKeySecretRef.name',message:'credential Secret names are immutable; rotate their content'}];
const definitions = [
  ['AsteriusTenantBinding','asteriustenantbindings',binding],
  ['Application','applications',application],
  ['Resource','resources',resource],
  ['Policy','policies',policy],
];
export const crds = definitions.map(([kind,plural,spec]) => ({
  apiVersion:'apiextensions.k8s.io/v1', kind:'CustomResourceDefinition',
  metadata:{name:`${plural}.identity.asterius.io`},
  spec:{group:'identity.asterius.io',scope:'Namespaced',names:{kind,plural,singular:kind.toLowerCase()},
    versions:[{name:'v1alpha1',served:true,storage:true,subresources:{status:{}},
      schema:{openAPIV3Schema:obj({apiVersion:str(),kind:str(),metadata:{type:'object'},spec,status},['spec'])},
      additionalPrinterColumns:[{name:'Ready',type:'string',jsonPath:'.status.conditions[?(@.type=="Ready")].status'},
        {name:'Generation',type:'integer',jsonPath:'.status.observedGeneration'}],
    }]},
}));

export function namespaceDocuments(namespace, secretNames=['asterius-auth-key','asterius-dpop-key','asterius-ca','application-public-jwks']) {
  const managed = ['applications','resources','policies'];
  const meta = name => ({name,namespace});
  const bindingName = `asterius-${namespace}`;
  const role = (roleName,rules) => ({apiVersion:'rbac.authorization.k8s.io/v1',kind:'Role',metadata:meta(roleName),rules});
  const roleBinding = (roleName,subject) => ({apiVersion:'rbac.authorization.k8s.io/v1',kind:'RoleBinding',metadata:meta(roleName),
    subjects:[subject],roleRef:{apiGroup:'rbac.authorization.k8s.io',kind:'Role',name:roleName}});
  return [
    {apiVersion:'v1',kind:'ServiceAccount',metadata:meta('asterius-controller'),automountServiceAccountToken:false},
    role('asterius-controller',[
      {apiGroups:['identity.asterius.io'],resources:managed,verbs:['get','list','watch','patch','update']},
      {apiGroups:['identity.asterius.io'],resources:managed.map(x=>`${x}/status`),verbs:['get','patch','update']},
      {apiGroups:['identity.asterius.io'],resources:['asteriustenantbindings'],resourceNames:['default'],verbs:['get']},
      {apiGroups:[''],resources:['secrets'],resourceNames:secretNames,verbs:['get']},
      {apiGroups:['coordination.k8s.io'],resources:['leases'],resourceNames:['asterius-controller'],verbs:['get','update','patch']},
    ]),
    roleBinding('asterius-controller',{kind:'ServiceAccount',name:'asterius-controller',namespace}),
    role('asterius-gitops',[
      {apiGroups:['identity.asterius.io'],resources:managed,verbs:['get','list','watch','create','patch','update','delete']},
      {apiGroups:['identity.asterius.io'],resources:['asteriustenantbindings'],resourceNames:['default'],verbs:['get']},
    ]),
    roleBinding('asterius-gitops',{kind:'Group',name:`asterius-gitops:${namespace}`,apiGroup:'rbac.authorization.k8s.io'}),
    {apiVersion:'coordination.k8s.io/v1',kind:'Lease',metadata:meta('asterius-controller'),spec:{leaseDurationSeconds:30}},
    {apiVersion:'admissionregistration.k8s.io/v1',kind:'ValidatingAdmissionPolicy',metadata:{name:bindingName},
      spec:{failurePolicy:'Fail',paramKind:{apiVersion:'identity.asterius.io/v1alpha1',kind:'AsteriusTenantBinding'},
        matchConstraints:{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':namespace}},
          resourceRules:[{apiGroups:['identity.asterius.io'],apiVersions:['v1alpha1'],operations:['CREATE','UPDATE'],resources:managed}]},
        validations:[{expression:`request.namespace == '${namespace}' && object.spec.tenantRef == params.metadata.name`,
          message:'identity must reference the administrator-owned binding in its own namespace'},
          {expression:`oldObject == null || !has(oldObject.metadata.finalizers) || !oldObject.metadata.finalizers.exists(f, f == 'identity.asterius.io/remote-resource') || (has(object.metadata.finalizers) && object.metadata.finalizers.exists(f, f == 'identity.asterius.io/remote-resource')) || request.userInfo.username == 'system:serviceaccount:${namespace}:asterius-controller' || authorizer.group('identity.asterius.io').resource('asteriustenantbindings').namespace(request.namespace).name('default').check('update').allowed()`,
            message:'only the controller or binding administrator may remove the identity finalizer'}],
      }},
    {apiVersion:'admissionregistration.k8s.io/v1',kind:'ValidatingAdmissionPolicyBinding',metadata:{name:bindingName},
      spec:{policyName:bindingName,validationActions:['Deny'],paramRef:{name:'default',namespace,parameterNotFoundAction:'Deny'}}},
  ];
}

export const examples = [
  {apiVersion:'v1',kind:'Namespace',metadata:{name:'identity-acme'}},
  {apiVersion:'identity.asterius.io/v1alpha1',kind:'AsteriusTenantBinding',metadata:{name:'default',namespace:'identity-acme'},spec:{
    tenantId:'acme',issuer:'https://idp.example/t/acme',clientId:'c.controller-acme',clusterId:'production',
    authenticationKeySecretRef:{name:'asterius-auth-key',key:'key.pem'},dpopKeySecretRef:{name:'asterius-dpop-key',key:'key.pem'},
    issuerCaSecretRef:{name:'asterius-ca',key:'ca.pem'},
  }},
  {apiVersion:'identity.asterius.io/v1alpha1',kind:'Application',metadata:{name:'billing',namespace:'identity-acme'},spec:{
    tenantRef:'default',clientName:'Billing',redirectUris:['https://billing.example/callback'],
    grantTypes:['authorization_code','refresh_token'],scopes:['openid','offline_access'],resources:['https://billing-api.example/'],
    jwksUri:'https://billing.example/jwks',deletionProtection:true,deletionPolicy:'Retain',adoptionPolicy:'Never',
  }},
  {apiVersion:'identity.asterius.io/v1alpha1',kind:'Resource',metadata:{name:'billing',namespace:'identity-acme'},spec:{
    tenantRef:'default',identifier:'https://billing-api.example/',scopes:['read','write'],defaultTokenLifetimeSeconds:300,
    introspectionClients:[],deletionProtection:true,deletionPolicy:'Retain',
  }},
  {apiVersion:'identity.asterius.io/v1alpha1',kind:'Policy',metadata:{name:'tenant',namespace:'identity-acme'},spec:{
    tenantRef:'default',rulesJson:JSON.stringify({version:1,rules:[]}),deletionProtection:true,deletionPolicy:'Retain',
  }},
];

if (process.argv.includes('--write')) {
  for (const [file,items] of [['crds.json',crds],['namespace-acme.json',namespaceDocuments('identity-acme')],['examples.json',examples]]) {
    writeFileSync(fileURLToPath(new URL(`../../deploy/operator/${file}`,import.meta.url)),JSON.stringify({apiVersion:'v1',kind:'List',items},null,2)+'\n');
  }
  for (const crd of crds) {
    writeFileSync(fileURLToPath(new URL(`../../charts/asterius-operator/crds/${crd.metadata.name}.yaml`,import.meta.url)),JSON.stringify(crd,null,2)+'\n');
  }
}
