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
package org.eclipse.microprofile.jwt;

import javax.security.auth.Subject;
import javax.security.enterprise.CallerPrincipal;
import java.util.Set;

/**
 *
 */

public class WrappedCallerPrincipal extends CallerPrincipal implements JWTPrincipal {

    private final JWTPrincipal wrappedPrincipal;

    public WrappedCallerPrincipal(JWTPrincipal jwtPrincipal) {
        super(jwtPrincipal.getName());
        this.wrappedPrincipal = jwtPrincipal;
    }

    @Override
    public String getRawToken() {
        return wrappedPrincipal.getRawToken();
    }

    @Override
    public String getIssuer() {
        return wrappedPrincipal.getIssuer();
    }

    @Override
    public String[] getAudience() {
        return wrappedPrincipal.getAudience();
    }

    @Override
    public String getSubject() {
        return wrappedPrincipal.getSubject();
    }

    @Override
    public String getTokenID() {
        return wrappedPrincipal.getTokenID();
    }

    @Override
    public long getExpirationTime() {
        return wrappedPrincipal.getExpirationTime();
    }

    @Override
    public long getIssuedAtTime() {
        return wrappedPrincipal.getIssuedAtTime();
    }

    @Override
    public Set<String> getGroups() {
        return wrappedPrincipal.getGroups();
    }

    @Override
    public Set<String> getRoles() {
        return wrappedPrincipal.getRoles();
    }

    @Override
    public Set<String> getOtherClaimNames() {
        return wrappedPrincipal.getOtherClaimNames();
    }

    @Override
    public Object getOtherClaim(String name) {
        return wrappedPrincipal.getOtherClaim(name);
    }

    @Override
    public boolean implies(Subject subject) {
        return wrappedPrincipal.implies(subject);
    }
}
