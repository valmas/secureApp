package com.valmas.secureApp.security;

import io.vavr.Tuple;
import io.vavr.control.Option;
import io.vavr.control.Try;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;

@Slf4j
class CipherUtils {

    @NonNull
    static String decryptPassword(final @NonNull String keystorePassword,
                                  final @NonNull String alias,
                                  final @NonNull String base64password){
        try {
            final byte[] encrypted = Base64.getDecoder().decode(base64password);
            final PublicKey publicKey = loadCertificate(keystorePassword, alias);
            final byte[] decrypted = decrypt(publicKey, encrypted);
            return new String(decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    @Nullable
    private static PublicKey loadCertificate(String keystorePassword, String alias) {
        return Try.of(() -> KeyStore.getInstance("PKCS12"))
                .mapTry(it -> {
                    final InputStream keystoreFile = CipherUtils.class.getResourceAsStream("/keystore.p12");
                    it.load(keystoreFile, keystorePassword.toCharArray());
                    return it;
                }).mapTry(it -> it.getCertificate(alias)).map(Certificate::getPublicKey).getOrNull();
    }

    @NonNull
    private static byte[] decrypt(PublicKey publicKey, byte [] encrypted) {
        return Try.of(() -> Cipher.getInstance("RSA"))
                .mapTry(it -> {
                    it.init(Cipher.DECRYPT_MODE, publicKey);
                    return it.doFinal(encrypted);
                }).getOrElse(new byte[]{});
    }
}
