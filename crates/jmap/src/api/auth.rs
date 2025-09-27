use common::{Server, auth::AccessToken};
use directory::{Permission, QueryParams, backend::internal::manage::ManageDirectory};
use jmap_proto::{
    error::set::SetError,
    request::{
        CopyRequestMethod, GetRequestMethod, QueryChangesRequestMethod, QueryRequestMethod,
        RequestMethod, SetRequestMethod, method::MethodObject,
    },
};
use types::{
    acl::{Acl, AclGrant},
    collection::Collection,
    id::Id,
};
use utils::map::bitmap::Bitmap;

pub trait JmapAcl {
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
    fn assert_has_jmap_permission(
        &self,
        request: &RequestMethod,
        object: MethodObject,
    ) -> trc::Result<()>;
    fn assert_has_access(&self, to_account_id: Id, to_collection: Collection)
    -> trc::Result<&Self>;
}

impl JmapAcl for Server {
    async fn acl_set(
        &self,
        changes: &mut Vec<AclGrant>,
        current: Option<&[AclGrant]>,
        acl_changes: MaybePatchValue,
    ) -> Result<(), SetError> {
        match acl_changes {
            MaybePatchValue::Value(Value::Array(values)) => {
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
                    .with_key_value(Property::Acl)
                    .with_description("Invalid ACL property."));
            }
        }
        Ok(())
    }

    async fn map_acl_set(&self, acl_set: Vec<Value>) -> Result<Vec<AclGrant>, SetError> {
        let mut acls = Vec::with_capacity(acl_set.len() / 2);
        for item in acl_set.chunks_exact(2) {
            if let (Value::Str(account_name), Value::Number(grants)) = (&item[0], &item[1]) {
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
                            .with_key_value(Property::Acl)
                            .with_description(format!("Account {account_name} does not exist.")));
                    }
                    _ => {
                        return Err(SetError::forbidden()
                            .with_key_value(Property::Acl)
                            .with_description("Temporary server failure during lookup"));
                    }
                }
            } else {
                return Err(SetError::invalid_properties()
                    .with_key_value(Property::Acl)
                    .with_description("Invalid ACL value found."));
            }
        }

        Ok(acls)
    }

    async fn map_acl_patch(
        &self,
        acl_patch: Vec<Value>,
    ) -> Result<(AclGrant, Option<bool>), SetError> {
        if let (Value::Str(account_name), Value::Number(grants)) = (&acl_patch[0], &acl_patch[1]) {
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
                    .with_key_value(Property::Acl)
                    .with_description(format!("Account {account_name} does not exist."))),
                _ => Err(SetError::forbidden()
                    .with_key_value(Property::Acl)
                    .with_description("Temporary server failure during lookup")),
            }
        } else {
            Err(SetError::invalid_properties()
                .with_key_value(Property::Acl)
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

    fn assert_has_jmap_permission(
        &self,
        request: &RequestMethod,
        object: MethodObject,
    ) -> trc::Result<()> {
        let permission = match request {
            RequestMethod::Get(m) => match &m {
                GetRequestMethod::Email(_) => Permission::JmapEmailGet,
                GetRequestMethod::Mailbox(_) => Permission::JmapMailboxGet,
                GetRequestMethod::Thread(_) => Permission::JmapThreadGet,
                GetRequestMethod::Identity(_) => Permission::JmapIdentityGet,
                GetRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionGet,
                GetRequestMethod::PushSubscription(_) => Permission::JmapPushSubscriptionGet,
                GetRequestMethod::Sieve(_) => Permission::JmapSieveScriptGet,
                GetRequestMethod::VacationResponse(_) => Permission::JmapVacationResponseGet,
                GetRequestMethod::Principal(_) => Permission::JmapPrincipalGet,
                GetRequestMethod::Quota(_) => Permission::JmapQuotaGet,
                GetRequestMethod::Blob(_) => Permission::JmapBlobGet,
            },
            RequestMethod::Set(m) => match &m {
                SetRequestMethod::Email(_) => Permission::JmapEmailSet,
                SetRequestMethod::Mailbox(_) => Permission::JmapMailboxSet,
                SetRequestMethod::Identity(_) => Permission::JmapIdentitySet,
                SetRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionSet,
                SetRequestMethod::PushSubscription(_) => Permission::JmapPushSubscriptionSet,
                SetRequestMethod::Sieve(_) => Permission::JmapSieveScriptSet,
                SetRequestMethod::VacationResponse(_) => Permission::JmapVacationResponseSet,
            },
            RequestMethod::Changes(_) => match object {
                MethodObject::Email => Permission::JmapEmailChanges,
                MethodObject::Mailbox => Permission::JmapMailboxChanges,
                MethodObject::Thread => Permission::JmapThreadChanges,
                MethodObject::Identity => Permission::JmapIdentityChanges,
                MethodObject::EmailSubmission => Permission::JmapEmailSubmissionChanges,
                MethodObject::Quota => Permission::JmapQuotaChanges,
                MethodObject::Core
                | MethodObject::Blob
                | MethodObject::PushSubscription
                | MethodObject::SearchSnippet
                | MethodObject::VacationResponse
                | MethodObject::SieveScript
                | MethodObject::Principal => Permission::JmapEmailChanges, // Unimplemented
            },
            RequestMethod::Copy(m) => match &m {
                CopyRequestMethod::Email(_) => Permission::JmapEmailCopy,
                CopyRequestMethod::Blob(_) => Permission::JmapBlobCopy,
            },
            RequestMethod::ImportEmail(_) => Permission::JmapEmailImport,
            RequestMethod::ParseEmail(_) => Permission::JmapEmailParse,
            RequestMethod::QueryChanges(m) => match m {
                QueryChangesRequestMethod::Email(_) => Permission::JmapEmailQueryChanges,
                QueryChangesRequestMethod::Mailbox(_) => Permission::JmapMailboxQueryChanges,
                QueryChangesRequestMethod::EmailSubmission(_) => {
                    Permission::JmapEmailSubmissionQueryChanges
                }
                QueryChangesRequestMethod::Sieve(_) => Permission::JmapSieveScriptQueryChanges,
                QueryChangesRequestMethod::Principal(_) => Permission::JmapPrincipalQueryChanges,
                QueryChangesRequestMethod::Quota(_) => Permission::JmapQuotaQueryChanges,
            },
            RequestMethod::Query(m) => match m {
                QueryRequestMethod::Email(_) => Permission::JmapEmailQuery,
                QueryRequestMethod::Mailbox(_) => Permission::JmapMailboxQuery,
                QueryRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionQuery,
                QueryRequestMethod::Sieve(_) => Permission::JmapSieveScriptQuery,
                QueryRequestMethod::Principal(_) => Permission::JmapPrincipalQuery,
                QueryRequestMethod::Quota(_) => Permission::JmapQuotaQuery,
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
