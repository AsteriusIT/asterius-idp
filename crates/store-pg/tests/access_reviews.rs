//! Real transactional governance regressions. Slow PostgreSQL tests run in CI.
use std::str::FromStr as _;
use asterius_domain::access_reviews::{AccessReviews,ApplyStatus,ConfigureOwnership,Decision,StartReview,Target};
use asterius_domain::{ApplicationRole,ApplicationRoleDirectory,DomainError,Group,GroupDirectory,GroupMetadata,RoleName,RoleOwner,TenantId,UserId};
use asterius_store_pg::{MIGRATOR,PgAccessReviews,PgApplicationRoles,PgGroups};
use sqlx::{PgPool,postgres::{PgConnectOptions,PgPoolOptions}};
use time::{Duration,OffsetDateTime};
use uuid::Uuid;

struct Db {pool:PgPool,schema:String,tenant:TenantId,owner:UserId,reviewer:UserId,user:UserId,reviews:PgAccessReviews,roles:PgApplicationRoles,groups:PgGroups}
impl Db {
 async fn setup()->Self{
  let url=std::env::var("DATABASE_URL").expect("ignored governance tests require DATABASE_URL");
  let schema=format!("access_reviews_{}",Uuid::new_v4().simple());
  let admin=PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
  sqlx::query(&format!("create schema {schema}")).execute(&admin).await.unwrap();admin.close().await;
  let options=PgConnectOptions::from_str(&url).unwrap().options([("search_path",schema.as_str())]);
  let pool=PgPoolOptions::new().max_connections(5).connect_with(options).await.unwrap();MIGRATOR.run(&pool).await.unwrap();
  let tenant=TenantId::new("reviews");
  sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values('reviews','https://id.example/reviews','Reviews','https://api.example')").execute(&pool).await.unwrap();
  let owner=UserId::generate();let reviewer=UserId::generate();let user=UserId::generate();
  for (id,name,administrative) in [(owner,"owner",true),(reviewer,"reviewer",true),(user,"subject",false)]{
   sqlx::query("insert into users(tenant_id,user_id,username) values('reviews',$1,$2)").bind(id.as_uuid()).bind(name).execute(&pool).await.unwrap();
   if administrative {sqlx::query("insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('reviews',$1,'tenant_admin',false)").bind(id.as_uuid()).execute(&pool).await.unwrap();}
  }
  Self{reviews:PgAccessReviews::new(pool.clone()),roles:PgApplicationRoles::new(pool.clone()),groups:PgGroups::new(pool.clone()),pool,schema,tenant,owner,reviewer,user}
 }
 async fn now(&self)->OffsetDateTime{sqlx::query_scalar("select clock_timestamp()").fetch_one(&self.pool).await.unwrap()}
 async fn role(&self,name:&str)->RoleName{
  let name=RoleName::parse(name).unwrap();self.roles.define(&ApplicationRole{tenant:self.tenant.clone(),owner:RoleOwner::Tenant,name:name.clone(),description:Some("Bounded test role".into()),created_at:self.now().await}).await.unwrap();name
 }
 async fn group(&self,name:&str)->Group{self.groups.create(&self.tenant,&GroupMetadata::parse(name,name).unwrap(),self.now().await).await.unwrap()}
 async fn review(&self,target:Target)->(Uuid,Uuid){
  let owner=self.reviews.configure(&self.tenant,self.owner,ConfigureOwnership{target,owner_user_id:*self.owner.as_uuid(),reviewers:vec![*self.reviewer.as_uuid()],enabled:true,expected_revision:None}).await.unwrap();
  let review=self.reviews.start(&self.tenant,self.owner,StartReview{ownership_ids:vec![owner.id],reviewer_id:*self.reviewer.as_uuid(),due_at:self.now().await+Duration::hours(1)}).await.unwrap();
  let item=self.reviews.items(&self.tenant,self.reviewer,false,review.id,None,50).await.unwrap().remove(0);
  self.reviews.decide(&self.tenant,self.reviewer,review.id,item.id,Decision::Remove,"Assignment is no longer needed".into()).await.unwrap();(review.id,item.id)
 }
 async fn cleanup(self){sqlx::query(&format!("drop schema {} cascade",self.schema)).execute(&self.pool).await.unwrap();self.pool.close().await;}
}

#[tokio::test]
#[ignore="slow: requires migrated PostgreSQL; CI exercises actual governance commands"]
async fn access_review_removes_only_selected_membership_and_preserves_independent_roles(){
 let db=Db::setup().await;let role=db.role("reader").await;let first=db.group("first").await;let second=db.group("second").await;
 db.roles.assign(&db.tenant,db.user,&RoleOwner::Tenant,&role,db.now().await).await.unwrap();
 for group in [&first,&second]{db.groups.add_member(&db.tenant,group.id,db.user,db.now().await).await.unwrap();db.roles.assign_group(&db.tenant,group.id,&RoleOwner::Tenant,&role,db.now().await).await.unwrap();}
 let (review,item)=db.review(Target::Membership{group_id:first.id.as_uuid(),user_id:*db.user.as_uuid()}).await;
 let result=db.reviews.apply(&db.tenant,db.reviewer,review,item).await.unwrap();assert_eq!(result.apply_status,ApplyStatus::Removed);
 let roles=db.roles.effective_roles(&db.tenant,db.user).await.unwrap();assert_eq!(roles.len(),1);assert_eq!(roles[0].sources.len(),2);
 let members=db.groups.groups_for_user(&db.tenant,db.user,None,100).await.unwrap();assert_eq!(members.len(),1);assert_eq!(members[0].id,second.id);db.cleanup().await;
}

#[tokio::test]
#[ignore="slow: requires migrated PostgreSQL; CI exercises actual governance commands"]
async fn access_review_does_not_revoke_a_recreated_assignment(){
 let db=Db::setup().await;let role=db.role("reader").await;db.roles.assign(&db.tenant,db.user,&RoleOwner::Tenant,&role,db.now().await).await.unwrap();
 let (review,item)=db.review(Target::UserTenantRole{user_id:*db.user.as_uuid(),name:role.to_string()}).await;
 db.roles.withdraw(&db.tenant,db.user,&RoleOwner::Tenant,&role).await.unwrap();db.roles.assign(&db.tenant,db.user,&RoleOwner::Tenant,&role,db.now().await).await.unwrap();
 assert_eq!(db.reviews.apply(&db.tenant,db.reviewer,review,item).await.unwrap().apply_status,ApplyStatus::Conflict);
 assert!(!db.roles.held_by(&db.tenant,db.user).await.unwrap().tenant.is_empty());db.cleanup().await;
}

#[tokio::test]
#[ignore="slow: requires migrated PostgreSQL; CI exercises actual governance commands"]
async fn access_review_group_role_rejects_a_member_added_after_snapshot(){
 let db=Db::setup().await;let role=db.role("reader").await;let group=db.group("engineering").await;
 db.groups.add_member(&db.tenant,group.id,db.user,db.now().await).await.unwrap();db.roles.assign_group(&db.tenant,group.id,&RoleOwner::Tenant,&role,db.now().await).await.unwrap();
 let (review,item)=db.review(Target::GroupTenantRole{group_id:group.id.as_uuid(),name:role.to_string()}).await;
 db.groups.add_member(&db.tenant,group.id,db.owner,db.now().await).await.unwrap();
 assert_eq!(db.reviews.apply(&db.tenant,db.reviewer,review,item).await.unwrap().apply_status,ApplyStatus::Conflict);
 assert!(!db.roles.held_by(&db.tenant,db.owner).await.unwrap().tenant.is_empty());db.cleanup().await;
}

#[tokio::test]
#[ignore="slow: requires migrated PostgreSQL; CI exercises actual governance commands"]
async fn access_review_controller_ownership_is_never_impersonated(){
 let db=Db::setup().await;let group=db.group("managed").await;db.groups.add_member(&db.tenant,group.id,db.user,db.now().await).await.unwrap();
 sqlx::query("update declarative_owners set owner='urn:test:controller',deletion_protection=false where tenant_id=$1 and kind='group' and keys=jsonb_build_array($2::text)")
  .bind(db.tenant.as_str()).bind(group.id.as_uuid()).execute(&db.pool).await.unwrap();
 let (review,item)=db.review(Target::Membership{group_id:group.id.as_uuid(),user_id:*db.user.as_uuid()}).await;
 assert_eq!(db.reviews.apply(&db.tenant,db.reviewer,review,item).await.unwrap().apply_status,ApplyStatus::Protected);
 assert_eq!(db.groups.groups_for_user(&db.tenant,db.user,None,100).await.unwrap().len(),1);db.cleanup().await;
}

#[tokio::test]
#[ignore="slow: requires migrated PostgreSQL; CI exercises actual governance commands"]
async fn access_review_rechecks_current_reviewer_authority_and_tenant_scope(){
 let db=Db::setup().await;let role=db.role("reader").await;db.roles.assign(&db.tenant,db.user,&RoleOwner::Tenant,&role,db.now().await).await.unwrap();
 let (review,item)=db.review(Target::UserTenantRole{user_id:*db.user.as_uuid(),name:role.to_string()}).await;
 assert!(matches!(db.reviews.apply(&TenantId::new("other"),db.reviewer,review,item).await,Err(DomainError::NotFound)));
 assert!(matches!(db.reviews.apply(&db.tenant,db.owner,review,item).await,Err(DomainError::NotFound)));
 sqlx::query("delete from user_roles where tenant_id=$1 and user_id=$2").bind(db.tenant.as_str()).bind(db.reviewer.as_uuid()).execute(&db.pool).await.unwrap();
 assert!(db.reviews.apply(&db.tenant,db.reviewer,review,item).await.is_err());
 assert!(!db.roles.held_by(&db.tenant,db.user).await.unwrap().tenant.is_empty());db.cleanup().await;
}

#[tokio::test]
#[ignore="slow: requires migrated PostgreSQL; CI exercises actual governance commands"]
async fn access_review_failed_audit_rolls_back_removal_and_application_result(){
 let db=Db::setup().await;let role=db.role("reader").await;db.roles.assign(&db.tenant,db.user,&RoleOwner::Tenant,&role,db.now().await).await.unwrap();
 let (review,item)=db.review(Target::UserTenantRole{user_id:*db.user.as_uuid(),name:role.to_string()}).await;
 sqlx::raw_sql("create function refuse_review_audit() returns trigger language plpgsql as $$ begin raise exception 'controlled audit refusal';end $$;create trigger refuse_review_audit before insert on audit_events for each row execute function refuse_review_audit();").execute(&db.pool).await.unwrap();
 assert!(db.reviews.apply(&db.tenant,db.reviewer,review,item).await.is_err());
 assert!(!db.roles.held_by(&db.tenant,db.user).await.unwrap().tenant.is_empty());
 assert_eq!(db.reviews.items(&db.tenant,db.reviewer,false,review,None,10).await.unwrap()[0].apply_status,ApplyStatus::Pending);db.cleanup().await;
}

#[tokio::test]
#[ignore="slow: requires migrated PostgreSQL; CI exercises multiple connection governance retry"]
async fn access_review_two_connections_apply_once_and_return_the_durable_result(){
 let db=Db::setup().await;let role=db.role("reader").await;db.roles.assign(&db.tenant,db.user,&RoleOwner::Tenant,&role,db.now().await).await.unwrap();
 let (review,item)=db.review(Target::UserTenantRole{user_id:*db.user.as_uuid(),name:role.to_string()}).await;
 let (left,right)=tokio::join!(db.reviews.apply(&db.tenant,db.reviewer,review,item),db.reviews.apply(&db.tenant,db.reviewer,review,item));
 assert_eq!(left.unwrap().apply_status,ApplyStatus::Removed);assert_eq!(right.unwrap().apply_status,ApplyStatus::Removed);
 let applications:i64=sqlx::query_scalar("select count(*) from audit_events where tenant_id=$1 and detail->>'operation'='governance.review.apply'")
  .bind(db.tenant.as_str()).fetch_one(&db.pool).await.unwrap();assert_eq!(applications,1);db.cleanup().await;
}
