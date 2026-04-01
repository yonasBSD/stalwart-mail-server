/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::{TaskFailureType, TaskResult};
use common::{Server, network::acme::AcmeError};
use registry::schema::structs::TaskDomainManagement;
use store::write::now;

pub(crate) trait AcmeTask: Sync + Send {
    fn acme_management(
        &self,
        task: &TaskDomainManagement,
    ) -> impl Future<Output = TaskResult> + Send;
}

impl AcmeTask for Server {
    async fn acme_management(&self, task: &TaskDomainManagement) -> TaskResult {
        match acme_management(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to run ACME task")
                );
                result
            }
        }
    }
}

async fn acme_management(server: &Server, task: &TaskDomainManagement) -> trc::Result<TaskResult> {
    match server.acme_renew(task.domain_id).await {
        Ok(tasks) => Ok(TaskResult::Success(tasks)),
        Err(err) => match err {
            AcmeError::Crypto(_)
            | AcmeError::Invalid(_)
            | AcmeError::ChallengeNotSupported { .. }
            | AcmeError::OrderInvalid
            | AcmeError::AuthInvalid(_)
            | AcmeError::Json(_)
            | AcmeError::Registry(_) => Ok(TaskResult::permanent(err.to_string())),
            AcmeError::Http(_) | AcmeError::HttpStatus(_) | AcmeError::Dns(_) => {
                Ok(TaskResult::temporary(err.to_string()))
            }
            AcmeError::OrderTimeout { max_retries } | AcmeError::AuthTimeout { max_retries } => {
                Ok(TaskResult::Failure {
                    typ: TaskFailureType::Temporary,
                    message: err.to_string(),
                    max_attempts: (max_retries as u64).into(),
                })
            }
            AcmeError::Backoff { max_retries, wait } => {
                if let Some(wait) = wait {
                    Ok(TaskResult::Failure {
                        typ: TaskFailureType::Retry(now() + wait.as_secs()),
                        message: err.to_string(),
                        max_attempts: (max_retries as u64).into(),
                    })
                } else {
                    Ok(TaskResult::Failure {
                        typ: TaskFailureType::Temporary,
                        message: err.to_string(),
                        max_attempts: (max_retries as u64).into(),
                    })
                }
            }
            AcmeError::Internal(error) => Err(error),
        },
    }
}
