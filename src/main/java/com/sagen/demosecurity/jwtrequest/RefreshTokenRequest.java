package com.sagen.demosecurity.jwtrequest;

import lombok.Data;

@Data
public class RefreshTokenRequest {
    private String refreshToken;
}
