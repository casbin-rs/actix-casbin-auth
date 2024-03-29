use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{
    body::MessageBody, dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage, HttpResponse,
};
use futures::future::{ok, Future, Ready};

use actix_casbin_auth::{CasbinService, CasbinVals};

use actix_web::{test, web, App};
use casbin::function_map::key_match2;
use casbin::{CoreApi, DefaultModel, FileAdapter};

pub struct FakeAuth;

impl<S, B> Transform<S, ServiceRequest> for FakeAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = FakeAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(FakeAuthMiddleware {
            service: Rc::new(RefCell::new(service)),
        })
    }
}

pub struct FakeAuthMiddleware<S> {
    service: Rc<RefCell<S>>,
}

impl<S, B> Service<ServiceRequest> for FakeAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        Box::pin(async move {
            let vals = CasbinVals {
                subject: String::from("alice"),
                domain: None,
            };
            req.extensions_mut().insert(vals);
            svc.call(req).await
        })
    }
}

#[actix_rt::test]
async fn test_middleware() {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_middleware = CasbinService::new(m, a).await.unwrap();

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(key_match2), None);

    let mut app = test::init_service(
        App::new()
            .wrap(casbin_middleware.clone())
            .wrap(FakeAuth)
            .route("/pen/1", web::get().to(|| HttpResponse::Ok()))
            .route("/book/{id}", web::get().to(|| HttpResponse::Ok())),
    )
    .await;

    let req_pen = test::TestRequest::get().uri("/pen/1").to_request();
    let resp_pen = test::call_service(&mut app, req_pen).await;
    assert!(resp_pen.status().is_success());

    let req_book = test::TestRequest::get().uri("/book/2").to_request();
    let resp_book = test::call_service(&mut app, req_book).await;
    assert!(resp_book.status().is_success());
}
