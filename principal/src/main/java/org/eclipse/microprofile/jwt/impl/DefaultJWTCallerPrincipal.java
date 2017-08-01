/*
 * Copyright 2017 Rudy De Busscher (www.c4j.be)
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

import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;

import javax.security.auth.Subject;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A default implementation of JWTCallerPrincipal.
 */
public class DefaultJWTCallerPrincipal extends JWTCallerPrincipal {

    private static Set<String> OTHER_CLAIM_NAMES;

    static {
        // Initialize the other claim names to some of the key ones in OIDC/OAuth2 but not MP JWT
        Set<String> tmp = new HashSet<>();
        tmp.add("nbf");
        tmp.add("auth_time");
        tmp.add("azp");
        tmp.add("nonce");
        tmp.add("acr");
        tmp.add("at_hash");
        tmp.add("name");
        tmp.add("given_name");
        tmp.add("family_name");
        tmp.add("email");
        tmp.add("email_verified");
        tmp.add("zoneinfo");
        tmp.add("website");
        tmp.add("preferred_username");
        tmp.add("updated_at");
        OTHER_CLAIM_NAMES = Collections.unmodifiableSet(tmp);
    }

    private final String token;
    private final JWTClaimsSet claimsSet;


    /**
     * Create the DefaultJWTCallerPrincipal from the parsed JWT token and the extracted principal name
     *
     * @param name - the extracted unqiue name to use as the principal name; from "upn", "preferred_username" or "sub" claim
     */

    public DefaultJWTCallerPrincipal(String token, JWTClaimsSet claimsSet, String name) {
        super(name);
        this.token = token;
        this.claimsSet = claimsSet;
    }

    @Override
    public String getRawToken() {
        return token;
    }

    @Override
    public String getIssuer() {
        return claimsSet.getIssuer();
    }

    @Override
    public String[] getAudience() {
        String[] result = new String[claimsSet.getAudience().size()];
        claimsSet.getAudience().toArray(result);
        return result;
    }

    @Override
    public String getSubject() {
        return claimsSet.getSubject();
    }

    @Override
    public String getTokenID() {
        return claimsSet.getJWTID();
    }

    @Override
    public long getExpirationTime() {
        return claimsSet.getExpirationTime().getTime() / 1000;
    }

    @Override
    public long getIssuedAtTime() {
        return claimsSet.getIssueTime().getTime() / 1000;
    }

    @Override
    public Set<String> getGroups() {
        HashSet<String> groups = new HashSet<>();
        // First look to the global level
        List<String> globalGroups = null;
        try {
            globalGroups = claimsSet.getStringListClaim("groups");
        } catch (ParseException e) {
            e.printStackTrace();
            // FIXME
        }
        if (globalGroups != null) {
            groups.addAll(globalGroups);
        }
        return groups;
    }

    @Override
    public Set<String> getRoles() {
        HashSet<String> roles = new HashSet<>();
        // First look to the global level
        List<String> globalRoles = null;
        try {
            globalRoles = claimsSet.getStringListClaim("roles");
        } catch (ParseException e) {
            e.printStackTrace();
            // FIXME
        }
        if (globalRoles != null) {
            roles.addAll(globalRoles);
        }
        return roles;
    }

    /**
     * Access the standard but non-MP mandated claim names this token may have. Note that the token may have even more
     * custom claims avaialable via the {@link #getOtherClaim(String)} method.
     *
     * @return standard but non-MP mandated claim names this token may have.
     */
    @Override
    public Set<String> getOtherClaimNames() {
        return OTHER_CLAIM_NAMES;
    }

    @Override
    public Object getOtherClaim(String claimName) {
        return claimsSet.getClaim(claimName);
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }

    public String toString() {
        return toString(false);
    }

    /**
     * TODO: showAll is ignored and currently assumed true
     *
     * @param showAll - should all claims associated with the JWT be displayed or should only those defined in the
     *                JWTPrincipal interface be displayed.
     * @return JWTCallerPrincipal string view
     */
    @Override
    public String toString(boolean showAll) {
        return null;
    }

}
