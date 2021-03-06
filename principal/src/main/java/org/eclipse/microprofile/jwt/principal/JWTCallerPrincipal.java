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
package org.eclipse.microprofile.jwt.principal;

import org.eclipse.microprofile.jwt.JWTPrincipal;

import java.security.Principal;

/**
 * An abstract CallerPrincipal implementation that provides access to the JWT claims that are required by
 * the microprofile token.
 */
public abstract class JWTCallerPrincipal implements Principal, JWTPrincipal {
    /**
     * The character to use to encode service specific groups/roles in the groups/roles set
     *
     * @see #getRoles()
     */
    public static final char SERVICE_NAME_SEPARATOR = ';';

    private final String name;

    /**
     * Create a JWTCallerPrincipal with the caller's name
     *
     * @param name - caller's name
     */
    public JWTCallerPrincipal(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    /**
     * Generate a human readable version of the caller principal and associated JWT.
     *
     * @param showAll - should all claims associated with the JWT be displayed or should only those defined in the
     *                JWTPrincipal interface be displayed.
     * @return human readable presentation of the caller principal and associated JWT.
     */
    public abstract String toString(boolean showAll);
}
