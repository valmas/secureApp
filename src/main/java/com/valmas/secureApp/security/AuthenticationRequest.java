package com.valmas.secureApp.security;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Data
@NoArgsConstructor
class AuthenticationRequest {

    @NonNull
    private String alias;
    @NonNull
    private String signature;
}
