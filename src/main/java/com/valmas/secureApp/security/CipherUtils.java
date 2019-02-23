package com.valmas.secureApp.security;

import io.vavr.control.Try;
import lombok.NonNull;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;

class CipherUtils {

    @NonNull
    static Try<String> decryptPassword(final @NonNull String keystorePassword,
                                       final @NonNull String alias,
                                       final @NonNull String base64password,
                                       final @NonNull String keystorePath) {

        return Try.of(() -> Base64.getDecoder().decode(base64password))
                .flatMap(enc -> loadCertificate(keystorePassword, alias, keystorePath)
                        .flatMap(pk -> decrypt(pk, enc))).map(String::new);
    }

    @NonNull
    private static Try<PublicKey> loadCertificate(final @NonNull String keystorePassword,
                                                  final @NonNull String alias,
                                                  final @NonNull String keystorePath) {
        return Try.of(() -> KeyStore.getInstance("PKCS12"))
                .mapTry(it -> {
                    final InputStream keystoreFile = CipherUtils.class.getResourceAsStream("/" + keystorePath);
                    it.load(keystoreFile, keystorePassword.toCharArray());
                    return it;
                }).mapTry(it -> it.getCertificate(alias)).map(Certificate::getPublicKey);
    }

    @NonNull
    private static Try<byte[]> decrypt(final @NonNull PublicKey publicKey,
                                       final @NonNull byte[] encrypted) {
        return Try.of(() -> Cipher.getInstance("RSA"))
                .mapTry(it -> {
                    it.init(Cipher.DECRYPT_MODE, publicKey);
                    return it.doFinal(encrypted);
                });
    }
}
