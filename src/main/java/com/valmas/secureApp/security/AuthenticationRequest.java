package com.valmas.secureApp.security;

import lombok.Data;
import lombok.NonNull;

@Data
class AuthenticationRequest {

    @NonNull
    private String alias;
    @NonNull
    private String signature;
}
