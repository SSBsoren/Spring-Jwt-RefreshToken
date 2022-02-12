package com.sagen.demosecurity.config;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class StatusResp extends AbstractResponse{
    private String msg;
    private String status;
}
