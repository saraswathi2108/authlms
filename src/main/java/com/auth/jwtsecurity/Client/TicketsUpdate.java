//package com.auth.jwtsecurity.Client;
//
//import com.auth.jwtsecurity.dto.Tickets;
//import org.springframework.cloud.openfeign.FeignClient;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//@FeignClient(name = "authentication-service",url = "https://hrms.anasolconsultancyservices.com")
//public interface TicketsUpdate {
//    @PostMapping("/api/ticket/auth/create")
//    ResponseEntity<Tickets> createAuth(@RequestBody Tickets Tickets);
//    @PutMapping("/api/ticket/auth/{employeeId}")
//    ResponseEntity<Tickets> updateAuth(@PathVariable String employeeId, @RequestBody Tickets Tickets);
//    @DeleteMapping("/api/ticket/auth/{employeeId}")
//    ResponseEntity<Void> deleteAuth(@PathVariable String employeeId);
//    @GetMapping("/api/ticket/auth/{employeeId}")
//    ResponseEntity<Tickets> getAuthByEmployeeId(@PathVariable String employeeId);
//}
