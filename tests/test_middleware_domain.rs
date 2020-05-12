use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage, HttpResponse};
use futures::future::{ok, Future, Ready};

use actix_casbin_auth::{CasbinService, CasbinVals};

use actix_web::{test, web, App};
use casbin::{DefaultModel, FileAdapter};

pub struct FakeAuth;

impl<S: 'static, B> Transform<S> for FakeAuth
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
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

impl<S, B> Service for FakeAuthMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut svc = self.service.clone();

        Box::pin(async move {
            let vals = CasbinVals {
                subject: String::from("alice"),
                domain: Option::from(String::from("domain1")),
            };
            req.extensions_mut().insert(vals);
            svc.call(req).await
        })
    }
}

#[actix_rt::test]
async fn test_middleware() {
    let m = DefaultModel::from_file("examples/rbac_with_domains_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_domains_policy.csv");

    let casbin_middleware = CasbinService::new(m, a).await;

    let mut app = test::init_service(
        App::new()
            .wrap(casbin_middleware)
            .wrap(FakeAuth)
            .route("/pen/1", web::get().to(|| HttpResponse::Ok()))
            .route("/book/1", web::get().to(|| HttpResponse::Ok())),
    )
    .await;

    let req_pen = test::TestRequest::get().uri("/pen/1").to_request();
    let resp_pen = test::call_service(&mut app, req_pen).await;
    assert!(resp_pen.status().is_success());

    let req_book = test::TestRequest::get().uri("/book/1").to_request();
    let resp_book = test::call_service(&mut app, req_book).await;
    assert!(!resp_book.status().is_success());
}
