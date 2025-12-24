//package com.auth.jwtsecurity.model;
//import jakarta.persistence.*;
//import jakarta.validation.constraints.NotNull;
//import lombok.Data;
//import lombok.NoArgsConstructor;
//import org.springframework.validation.annotation.Validated;
//
//import java.math.BigDecimal;
//@Data
//@Entity
//@NoArgsConstructor
//@Table(name = "employees")
//public class Employee {
//    @Id
//    @GeneratedValue(strategy = GenerationType.SEQUENCE)
//
//    private Long id;
//    @NotNull
//    @Column(nullable = false)
//    private String name;
//    @NotNull
//    @Column(nullable = false)
//    private BigDecimal price;
//    public Employee(String name, BigDecimal price) {
//        this.name = name;
//        this.price = price;
//    }
//}
//
package com.auth.jwtsecurity.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDateTime;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "OTPStore")
@Builder
public class OtpStore {
    @Id
    private String messageId;
    private LocalDateTime sentTime;
    private String otp;
    @ManyToOne
    @JoinColumn(name = "employee_id")
    private User employeeID;
    private Instant expiryTime;
    private Boolean verified;
}
