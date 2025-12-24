//package com.auth.jwtsecurity.Client;
//
//import feign.RequestInterceptor;
//import feign.RequestTemplate;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.stereotype.Component;
//
//@RequiredArgsConstructor
//@Slf4j
//@Component
//public class FeignClientInterceptor implements RequestInterceptor {
//
//    private final CustomFeignContext customFeignContext;
//
//    @Override
//    public void apply(RequestTemplate template) {
//        String token = customFeignContext.getToken();
//        log.info("looking for Fient Client info {} {}",customFeignContext, token );
//        if (token != null) {
//            template.header("Authorization", token);
//        } else {
//            log.warn("❌ No token found to forward in Feign request");
//        }
//    }
//
//
//}
