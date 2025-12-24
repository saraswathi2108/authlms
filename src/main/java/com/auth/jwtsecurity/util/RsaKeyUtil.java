package com.auth.jwtsecurity.util;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.stream.Collectors;
@Component
public class RsaKeyUtil {
    private static final Base64.Decoder DEC = Base64.getDecoder();
    private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();
    private final ResourceLoader resourceLoader;
    public RsaKeyUtil(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }
    public PrivateKey loadPrivateKey(String location) throws Exception {
        Resource resource = resourceLoader.getResource(location);
        String key = readKeyFromInputStream(resource);
        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }
    public PublicKey loadPublicKey(String location) throws Exception {
        Resource resource = resourceLoader.getResource(location);
        String key = readKeyFromInputStream(resource);
        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }
    private String readKeyFromInputStream(Resource resource) throws Exception {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
            return reader.lines().collect(Collectors.joining());
        }
    }
    public String rsaEncrypt(Base64.Encoder encoder, PublicKey pub, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] ct = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return encoder.encodeToString(ct);
    }

    public String rsaEncrypt(PublicKey pub, String plaintext) throws Exception {
        return rsaEncrypt(ENC, pub, plaintext);
    }

    // Decrypt using RSA OAEP (server uses private key to decrypt token)
    public String rsaDecrypt(PrivateKey priv, String base64CipherText) throws Exception {
        byte[] ct = Base64.getUrlDecoder().decode(base64CipherText);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, priv);
        byte[] pt = cipher.doFinal(ct);
        return new String(pt, "UTF-8");
    }
}
