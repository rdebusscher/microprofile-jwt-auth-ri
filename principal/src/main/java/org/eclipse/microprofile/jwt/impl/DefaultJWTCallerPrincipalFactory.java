/*
 * Copyright 017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.eclipse.microprofile.jwt.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;

import java.util.Date;


/**
 * A default implementation of the abstract JWTCallerPrincipalFactory that uses the Keycloak token parsing classes.
 */
public class DefaultJWTCallerPrincipalFactory extends JWTCallerPrincipalFactory {

    /**
     * Tries to load the JWTAuthContextInfo from CDI if the class level authContextInfo has not been set.
     */
    public DefaultJWTCallerPrincipalFactory() {
    }

    @Override
    public JWTCallerPrincipal parse(String token, JWTAuthContextInfo authContextInfo) throws ParseException {
        JWTCallerPrincipal principal = null;
        try {

            JWSVerifier verifier = new RSASSAVerifier(authContextInfo.getSignerKey());

            // Parse token
            SignedJWT signedJWT = SignedJWT.parse(token);

            JWTClaimsSet claimsSet;
            if (signedJWT.verify(verifier)) {
                // Signing is OK, do some other checks.
                claimsSet = signedJWT.getJWTClaimsSet();

                checkExpired(claimsSet, authContextInfo.getExpGracePeriodSecs());
                checkIssuer(claimsSet, authContextInfo.getIssuedBy());

                String principalName = determinePrincipalName(claimsSet);

                principal = new DefaultJWTCallerPrincipal(token, claimsSet, principalName);
            } else {
                throw new ParseException("Invalid signature");
            }

        } catch (JOSEException | java.text.ParseException e) {
            throw new ParseException("Failed to verify the input token", e);
        }
        return principal;
    }

    private String determinePrincipalName(JWTClaimsSet claimsSet) throws java.text.ParseException {
        // We have to determine the unique name to use as the principal name. It comes from upn, preferred_username, sub in that order
        String principalName = claimsSet.getStringClaim("upn");
        if (principalName == null) {
            principalName = claimsSet.getStringClaim("preferred_username");
            if (principalName == null) {
                principalName = claimsSet.getSubject();
            }
        }
        return principalName;
    }

    private void checkIssuer(JWTClaimsSet claimsSet, String issuedBy) throws ParseException {
        if (!issuedBy.equals(claimsSet.getIssuer())) {
            throw new ParseException("Token has wrong issuer");
        }
    }

    private void checkExpired(JWTClaimsSet claimsSet, int expGracePeriodSecs) throws ParseException {
        if (expGracePeriodSecs == -1) {
            // Is this a hack for the test only ?!
            // see org.eclipse.microprofile.jwt.test.format.TestTokenValidation.testRIJWTCallerPrincipal()
            return;
        }
        // TODO support only Java 8 and use LocalDateTime
        Date limit = new Date(System.currentTimeMillis() + expGracePeriodSecs * 1000);
        if (limit.after(claimsSet.getExpirationTime())) {
            throw new ParseException("Token Expired");
        }
    }
}
