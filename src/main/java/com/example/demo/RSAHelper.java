package com.example.demo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.experimental.UtilityClass;

import java.text.ParseException;

@UtilityClass
public class RSAHelper {

    public static RSAKey rsaJWK;

    static {
        try {
            rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
    }

    private static RSAKey publicKey() {
        return rsaJWK.toPublicJWK();
    }

    private static JWSSigner signer() throws JOSEException {
        return new RSASSASigner(rsaJWK);
    }

    public static String getJWSToken() throws JOSEException {
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                new Payload("In RSA we trust!"));

        jwsObject.sign(signer());

        return jwsObject.serialize();
    }

    public static boolean verifySigning(String jwsToken) {
        try {
            JWSObject jwsObject = JWSObject.parse(jwsToken);
            JWSVerifier verifier = new RSASSAVerifier(publicKey());
            return jwsObject.verify(verifier);
        } catch (ParseException | JOSEException e) {
            return false;
        }
    }
}
