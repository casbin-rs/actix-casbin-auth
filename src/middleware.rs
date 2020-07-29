#![allow(clippy::type_complexity)]

use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::{ok, Ready};
use futures::Future;

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage, HttpResponse};

use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi};

#[cfg(feature = "runtime-tokio")]
use tokio::sync::RwLock;

#[cfg(feature = "runtime-async-std")]
use async_std::sync::RwLock;

#[derive(Clone)]
pub struct CasbinVals {
    pub subject: String,
    pub domain: Option<String>,
}

#[derive(Clone)]
pub struct CasbinService {
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl CasbinService {
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> Self {
        let enforcer: CachedEnforcer = CachedEnforcer::new(m, a).await.unwrap();
        CasbinService {
            enforcer: Arc::new(RwLock::new(enforcer)),
        }
    }

    pub async fn get_enforcer(&mut self) -> Arc<RwLock<CachedEnforcer>> {
        self.enforcer.clone()
    }

    pub async fn set_enforcer(e: Arc<RwLock<CachedEnforcer>>) -> Self {
        CasbinService { enforcer: e }
    }
}

impl<S, B> Transform<S> for CasbinService
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CasbinMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CasbinMiddleware {
            enforcer: self.enforcer.clone(),
            service: Rc::new(RefCell::new(service)),
        })
    }
}

impl Deref for CasbinService {
    type Target = Arc<RwLock<CachedEnforcer>>;

    fn deref(&self) -> &Self::Target {
        &self.enforcer
    }
}

impl DerefMut for CasbinService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.enforcer
    }
}

pub struct CasbinMiddleware<S> {
    service: Rc<RefCell<S>>,
    enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl<S, B> Service for CasbinMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();
        let mut srv = self.service.clone();

        Box::pin(async move {
            let path = req.path().to_string();
            let action = req.method().as_str().to_string();
            let option_vals = req.extensions().get::<CasbinVals>().map(|x| x.to_owned());
            let vals = match option_vals {
                Some(value) => value,
                None => {
                    return Ok(req.into_response(HttpResponse::Unauthorized().finish().into_body()))
                }
            };
            let subject = &vals.subject;

            if !vals.subject.is_empty() {
                if let Some(domain) = &vals.domain {
                    let lock = cloned_enforcer.write().await;
                    match lock.enforce(&[subject, domain, &path, &action]) {
                        Ok(true) => {
                            let fut_res = srv.call(req);
                            fut_res.await
                        }
                        Ok(false) => {
                            Ok(req.into_response(HttpResponse::Forbidden().finish().into_body()))
                        }
                        Err(_) => {
                            Ok(req.into_response(HttpResponse::BadGateway().finish().into_body()))
                        }
                    }
                } else {
                    let lock = cloned_enforcer.write().await;
                    match lock.enforce(&[subject, &path, &action]) {
                        Ok(true) => {
                            let fut_res = srv.call(req);
                            fut_res.await
                        }
                        Ok(false) => {
                            Ok(req.into_response(HttpResponse::Forbidden().finish().into_body()))
                        }
                        Err(_) => {
                            Ok(req.into_response(HttpResponse::BadGateway().finish().into_body()))
                        }
                    }
                }
            } else {
                Ok(req.into_response(HttpResponse::Unauthorized().finish().into_body()))
            }
        })
    }
}
