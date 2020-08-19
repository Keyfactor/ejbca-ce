/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authentication.tokens;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.Objects;

import org.apache.commons.lang.StringUtils;

/**
 * OAuth2 principal that contains the JWT claim attributes.
 *
 * @version $Id$
 */
public class OAuth2Principal implements Principal, Serializable {

    private static final long serialVersionUID = 1L;

    private final String issuer;
    private final String subject;
    private final Collection<String> audience;

    /**
     * Creates an OAuth2 principal from JWT claim attributes.
     *
     * @param issuer Issuer, the "iss" attribute in the token. May be null.
     * @param subject Subject, the "sub" attribute in the token. May be null.
     * @param audience Audience list, the "aud" attribute in the token. May be empty, but not null.
     */
    public OAuth2Principal(final String issuer, final String subject, final Collection<String> audience) {
        Objects.requireNonNull(audience, "constructor does not allow null in the audience parameter");
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience;
    }

    @Override
    public String getName() {
        return subject != null ? subject : StringUtils.join(audience, ',');
    }

    /** Returns the issuer (corresponding to the "iss" attribute in the token), or null if absent */
    public String getIssuer() { return issuer; }
    /** Returns the subject (corresponding to the "sub" attribute in the token), or null if absent */
    public String getSubject() { return subject; }
    /** Returns the audience list (corresponding to the "aud" attribute in the token). Never null. */
    public Collection<String> getAudience() { return audience; }

    @Override
    public String toString() {
        return "[OAuth2 Principal, iss:" + issuer + " sub:" + subject + " aud:" + audience + "]";
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof OAuth2Principal)) {
            return false;
        }
        final OAuth2Principal other = (OAuth2Principal)obj;
        return StringUtils.equals(subject, other.subject) &&
                StringUtils.equals(issuer, other.issuer) &&
                audience.equals(other.audience);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, issuer, audience);
    }
}
