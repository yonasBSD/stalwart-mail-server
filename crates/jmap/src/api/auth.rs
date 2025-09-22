use common::{Server, auth::AccessToken};
use directory::{Permission, QueryParams, backend::internal::manage::ManageDirectory};
use jmap_proto::{
    error::set::SetError,
    request::RequestMethod,
    types::{
        property::Property,
        value::{MaybePatchValue, Value},
    },
};
use types::{
    acl::{Acl, AclGrant},
    collection::Collection,
    id::Id,
};
use utils::map::bitmap::Bitmap;

pub trait JmapAcl {
    fn acl_get(
        &self,
        value: &[AclGrant],
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = Value> + Send;
    fn acl_set(
        &self,
        changes: &mut Vec<AclGrant>,
        current: Option<&[AclGrant]>,
        acl_changes: MaybePatchValue,
    ) -> impl Future<Output = Result<(), SetError>> + Send;
    fn map_acl_set(
        &self,
        acl_set: Vec<Value>,
    ) -> impl Future<Output = Result<Vec<AclGrant>, SetError>> + Send;
    fn map_acl_patch(
        &self,
        acl_patch: Vec<Value>,
    ) -> impl Future<Output = Result<(AclGrant, Option<bool>), SetError>> + Send;
}

pub trait JmapAuthorization {
    fn assert_is_member(&self, account_id: Id) -> trc::Result<&Self>;
    fn assert_has_jmap_permission(&self, request: &RequestMethod) -> trc::Result<()>;
    fn assert_has_access(&self, to_account_id: Id, to_collection: Collection)
    -> trc::Result<&Self>;
}

impl JmapAcl for Server {
    async fn acl_get(
        &self,
        value: &[AclGrant],
        access_token: &AccessToken,
        account_id: u32,
    ) -> Value {
        if access_token.is_member(account_id)
            || value.iter().any(|item| {
                access_token.is_member(item.account_id) && item.grants.contains(Acl::Administer)
            })
        {
            let mut acl_obj = jmap_proto::types::value::Object::with_capacity(value.len() / 2);
            for item in value {
                if let Some(name) = self
                    .store()
                    .get_principal(item.account_id)
                    .await
                    .unwrap_or_default()
                {
                    acl_obj.append(
                        Property::_T(name.name),
                        item.grants
                            .map(|acl_item| Value::Text(acl_item.to_string()))
                            .collect::<Vec<_>>(),
                    );
                }
            }

            Value::Object(acl_obj)
        } else {
            Value::Null
        }
    }

    async fn acl_set(
        &self,
        changes: &mut Vec<AclGrant>,
        current: Option<&[AclGrant]>,
        acl_changes: MaybePatchValue,
    ) -> Result<(), SetError> {
        match acl_changes {
            MaybePatchValue::Value(Value::List(values)) => {
                *changes = self.map_acl_set(values).await?;
            }
            MaybePatchValue::Patch(patch) => {
                let (mut patch, is_update) = self.map_acl_patch(patch).await?;
                if let Some(changes_) = current {
                    *changes = changes_.to_vec();
                }

                if let Some(is_set) = is_update {
                    if !patch.grants.is_empty() {
                        if let Some(acl_item) = changes
                            .iter_mut()
                            .find(|item| item.account_id == patch.account_id)
                        {
                            let item = patch.grants.pop().unwrap();
                            if is_set {
                                acl_item.grants.insert(item);
                            } else {
                                acl_item.grants.remove(item);
                                if acl_item.grants.is_empty() {
                                    changes.retain(|item| item.account_id != patch.account_id);
                                }
                            }
                        } else if is_set {
                            changes.push(patch);
                        }
                    }
                } else if !patch.grants.is_empty() {
                    if let Some(acl_item) = changes
                        .iter_mut()
                        .find(|item| item.account_id == patch.account_id)
                    {
                        acl_item.grants = patch.grants;
                    } else {
                        changes.push(patch);
                    }
                } else {
                    changes.retain(|item| item.account_id != patch.account_id);
                }
            }
            _ => {
                return Err(SetError::invalid_properties()
                    .with_property(Property::Acl)
                    .with_description("Invalid ACL property."));
            }
        }
        Ok(())
    }

    async fn map_acl_set(&self, acl_set: Vec<Value>) -> Result<Vec<AclGrant>, SetError> {
        let mut acls = Vec::with_capacity(acl_set.len() / 2);
        for item in acl_set.chunks_exact(2) {
            if let (Value::Text(account_name), Value::UnsignedInt(grants)) = (&item[0], &item[1]) {
                match self
                    .core
                    .storage
                    .directory
                    .query(QueryParams::name(account_name).with_return_member_of(false))
                    .await
                {
                    Ok(Some(principal)) => {
                        acls.push(AclGrant {
                            account_id: principal.id(),
                            grants: Bitmap::from(*grants),
                        });
                    }
                    Ok(None) => {
                        return Err(SetError::invalid_properties()
                            .with_property(Property::Acl)
                            .with_description(format!("Account {account_name} does not exist.")));
                    }
                    _ => {
                        return Err(SetError::forbidden()
                            .with_property(Property::Acl)
                            .with_description("Temporary server failure during lookup"));
                    }
                }
            } else {
                return Err(SetError::invalid_properties()
                    .with_property(Property::Acl)
                    .with_description("Invalid ACL value found."));
            }
        }

        Ok(acls)
    }

    async fn map_acl_patch(
        &self,
        acl_patch: Vec<Value>,
    ) -> Result<(AclGrant, Option<bool>), SetError> {
        if let (Value::Text(account_name), Value::UnsignedInt(grants)) =
            (&acl_patch[0], &acl_patch[1])
        {
            match self
                .core
                .storage
                .directory
                .query(QueryParams::name(account_name).with_return_member_of(false))
                .await
            {
                Ok(Some(principal)) => Ok((
                    AclGrant {
                        account_id: principal.id(),
                        grants: Bitmap::from(*grants),
                    },
                    acl_patch.get(2).map(|v| v.as_bool().unwrap_or(false)),
                )),
                Ok(None) => Err(SetError::invalid_properties()
                    .with_property(Property::Acl)
                    .with_description(format!("Account {account_name} does not exist."))),
                _ => Err(SetError::forbidden()
                    .with_property(Property::Acl)
                    .with_description("Temporary server failure during lookup")),
            }
        } else {
            Err(SetError::invalid_properties()
                .with_property(Property::Acl)
                .with_description("Invalid ACL value found."))
        }
    }
}

impl JmapAuthorization for AccessToken {
    fn assert_is_member(&self, account_id: Id) -> trc::Result<&Self> {
        if self.is_member(account_id.document_id()) {
            Ok(self)
        } else {
            Err(trc::JmapEvent::Forbidden
                .into_err()
                .details(format!("You are not an owner of account {}", account_id)))
        }
    }

    fn assert_has_access(
        &self,
        to_account_id: Id,
        to_collection: Collection,
    ) -> trc::Result<&Self> {
        if self.has_access(to_account_id.document_id(), to_collection) {
            Ok(self)
        } else {
            Err(trc::JmapEvent::Forbidden.into_err().details(format!(
                "You do not have access to account {}",
                to_account_id
            )))
        }
    }

    fn assert_has_jmap_permission(&self, request: &RequestMethod) -> trc::Result<()> {
        let permission = match request {
            RequestMethod::Get(m) => match &m.arguments {
                jmap_proto::method::get::RequestArguments::Email(_) => Permission::JmapEmailGet,
                jmap_proto::method::get::RequestArguments::Mailbox => Permission::JmapMailboxGet,
                jmap_proto::method::get::RequestArguments::Thread => Permission::JmapThreadGet,
                jmap_proto::method::get::RequestArguments::Identity => Permission::JmapIdentityGet,
                jmap_proto::method::get::RequestArguments::EmailSubmission => {
                    Permission::JmapEmailSubmissionGet
                }
                jmap_proto::method::get::RequestArguments::PushSubscription => {
                    Permission::JmapPushSubscriptionGet
                }
                jmap_proto::method::get::RequestArguments::SieveScript => {
                    Permission::JmapSieveScriptGet
                }
                jmap_proto::method::get::RequestArguments::VacationResponse => {
                    Permission::JmapVacationResponseGet
                }
                jmap_proto::method::get::RequestArguments::Principal => {
                    Permission::JmapPrincipalGet
                }
                jmap_proto::method::get::RequestArguments::Quota => Permission::JmapQuotaGet,
                jmap_proto::method::get::RequestArguments::Blob(_) => Permission::JmapBlobGet,
            },
            RequestMethod::Set(m) => match &m.arguments {
                jmap_proto::method::set::RequestArguments::Email => Permission::JmapEmailSet,
                jmap_proto::method::set::RequestArguments::Mailbox(_) => Permission::JmapMailboxSet,
                jmap_proto::method::set::RequestArguments::Identity => Permission::JmapIdentitySet,
                jmap_proto::method::set::RequestArguments::EmailSubmission(_) => {
                    Permission::JmapEmailSubmissionSet
                }
                jmap_proto::method::set::RequestArguments::PushSubscription => {
                    Permission::JmapPushSubscriptionSet
                }
                jmap_proto::method::set::RequestArguments::SieveScript(_) => {
                    Permission::JmapSieveScriptSet
                }
                jmap_proto::method::set::RequestArguments::VacationResponse => {
                    Permission::JmapVacationResponseSet
                }
            },
            RequestMethod::Changes(m) => match m.arguments {
                jmap_proto::method::changes::RequestArguments::Email => {
                    Permission::JmapEmailChanges
                }
                jmap_proto::method::changes::RequestArguments::Mailbox => {
                    Permission::JmapMailboxChanges
                }
                jmap_proto::method::changes::RequestArguments::Thread => {
                    Permission::JmapThreadChanges
                }
                jmap_proto::method::changes::RequestArguments::Identity => {
                    Permission::JmapIdentityChanges
                }
                jmap_proto::method::changes::RequestArguments::EmailSubmission => {
                    Permission::JmapEmailSubmissionChanges
                }
                jmap_proto::method::changes::RequestArguments::Quota => {
                    Permission::JmapQuotaChanges
                }
            },
            RequestMethod::Copy(m) => match m.arguments {
                jmap_proto::method::copy::RequestArguments::Email => Permission::JmapEmailCopy,
            },
            RequestMethod::CopyBlob(_) => Permission::JmapBlobCopy,
            RequestMethod::ImportEmail(_) => Permission::JmapEmailImport,
            RequestMethod::ParseEmail(_) => Permission::JmapEmailParse,
            RequestMethod::QueryChanges(m) => match m.arguments {
                jmap_proto::method::query::RequestArguments::Email(_) => {
                    Permission::JmapEmailQueryChanges
                }
                jmap_proto::method::query::RequestArguments::Mailbox(_) => {
                    Permission::JmapMailboxQueryChanges
                }
                jmap_proto::method::query::RequestArguments::EmailSubmission => {
                    Permission::JmapEmailSubmissionQueryChanges
                }
                jmap_proto::method::query::RequestArguments::SieveScript => {
                    Permission::JmapSieveScriptQueryChanges
                }
                jmap_proto::method::query::RequestArguments::Principal => {
                    Permission::JmapPrincipalQueryChanges
                }
                jmap_proto::method::query::RequestArguments::Quota => {
                    Permission::JmapQuotaQueryChanges
                }
            },
            RequestMethod::Query(m) => match m.arguments {
                jmap_proto::method::query::RequestArguments::Email(_) => Permission::JmapEmailQuery,
                jmap_proto::method::query::RequestArguments::Mailbox(_) => {
                    Permission::JmapMailboxQuery
                }
                jmap_proto::method::query::RequestArguments::EmailSubmission => {
                    Permission::JmapEmailSubmissionQuery
                }
                jmap_proto::method::query::RequestArguments::SieveScript => {
                    Permission::JmapSieveScriptQuery
                }
                jmap_proto::method::query::RequestArguments::Principal => {
                    Permission::JmapPrincipalQuery
                }
                jmap_proto::method::query::RequestArguments::Quota => Permission::JmapQuotaQuery,
            },
            RequestMethod::SearchSnippet(_) => Permission::JmapSearchSnippet,
            RequestMethod::ValidateScript(_) => Permission::JmapSieveScriptValidate,
            RequestMethod::LookupBlob(_) => Permission::JmapBlobLookup,
            RequestMethod::UploadBlob(_) => Permission::JmapBlobUpload,
            RequestMethod::Echo(_) => Permission::JmapEcho,
            RequestMethod::Error(_) => return Ok(()),
        };

        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("You are not authorized to perform this action"))
        }
    }
}
