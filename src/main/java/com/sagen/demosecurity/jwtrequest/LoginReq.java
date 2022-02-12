package com.sagen.demosecurity.jwtrequest;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginReq {
    private String username;
    private String password;
}
