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
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang.StringUtils;

/**
 * OAuth2 principal that contains the JWT claim attributes.
 */
public class OAuth2Principal implements Principal, Serializable {

    private static final long serialVersionUID = 1L;

    // These are documented in https://openid.net/specs/openid-connect-core-1_0.html
    // Only attributes that might be meaningful to EJBCA have been added here
    private final int oauthProviderId;
    private final String issuer;
    private final String subject;
    private final String oid;
    private final Collection<String> audience;
    private final String preferredUsername;
    private final String name;
    private final String email;
    private final boolean emailVerified;
    private HashSet<String> roles;

    private OAuth2Principal(int oauthProviderId, String issuer, String subject, String oid, Collection<String> audience, String preferredUsername, String name,
            String email, final boolean emailVerified, Collection<String> roles) {
        this.oauthProviderId = oauthProviderId;
        this.issuer = issuer;
        this.subject = subject;
        this.oid = oid;
        this.audience = audience != null ? audience : Collections.emptySet();
        this.preferredUsername = preferredUsername;
        this.name = name;
        this.email = email;
        this.emailVerified = emailVerified;
        this.roles = new HashSet<>(roles);
    }

    /**
     * Returns a name of the token, suitable for logging. If present, this is the "preferred_username" attribute,
     * but it falls back to other attributes. To get specifically the "name" attribute,
     * call {@link #getNameAttribute}.
     */
    @Override
    public String getName() {
        if (StringUtils.isNotBlank(preferredUsername)) return preferredUsername;
        if (StringUtils.isNotBlank(oid)) return oid;
        if (StringUtils.isNotBlank(subject)) return subject;
        return StringUtils.join(audience, ',');
    }

    public String getDisplayName() {
        if (StringUtils.isNotBlank(name)) return name; // prefer display name over username
        if (StringUtils.isNotBlank(preferredUsername)) return preferredUsername;
        if (StringUtils.isNotBlank(email)) return email;
        if (StringUtils.isNotBlank(oid)) return oid;
        if (StringUtils.isNotBlank(subject)) return subject;
        return StringUtils.join(audience, ',');
    }

    /** returns id of trusted oauth provider where token came from */
    public Integer getOauthProviderId() {return oauthProviderId;}
    /** Returns the issuer (corresponding to the "iss" attribute in the token), or null if absent */
    public String getIssuer() { return issuer; }
    /** Returns the subject (corresponding to the "sub" attribute in the token), or null if absent */
    public String getSubject() { return subject; }
    /** Returns the object id (corresponding to the "oid" attribute in the token), or null if absent */
    public String getOid() { return oid; }
    /** Returns the audience list (corresponding to the "aud" attribute in the token). Never null. */
    public Collection<String> getAudience() { return audience; }

    public String getPreferredUsername() { return preferredUsername; }
    public String getEmail() { return email; }
    public String getNameAttribute() { return name; }
    public boolean isEmailVerified() { return emailVerified; }

    @Override
    public String toString() {
        return "[OAuth2 Principal, iss:" + issuer + " sub:" + subject + " oid:" + oid + " aud:" + audience + " roles:" + roles + "]";
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
                StringUtils.equals(oid, other.oid) &&
                roles.equals(roles) &&
                audience.equals(other.audience);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, issuer, audience, roles);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private int oauthProviderId;
        private String issuer;
        private String subject;
        private String oid;
        private Collection<String> audience;
        private String preferredUsername;
        private String name;
        private String email;
        private boolean emailVerified;
        private Collection<String> roles = new HashSet<>();

        public Builder setOauthProviderId(int oauthProviderId) {
            this.oauthProviderId = oauthProviderId;
            return this;
        }

        public Builder setIssuer(final String issuer) {
            this.issuer = issuer;
            return this;
        }
        
        public Builder setSubject(final String subject) {
            this.subject = subject;
            return this;
        }
        public Builder setOid(final String oid) {
            this.oid = oid;
            return this;
        }
        public Builder setAudience(final Collection<String> audience) {
            this.audience = audience;
            return this;
        }
        public Builder setPreferredUsername(String preferredUsername) {
            this.preferredUsername = preferredUsername;
            return this;
        }
        public Builder setEmail(String email) {
            this.email = email;
            return this;
        }
        public Builder setEmailVerified(final boolean emailVerified) {
            this.emailVerified = emailVerified;
            return this;
        }
        public Builder setName(final String name) {
            this.name = name;
            return this;
        }

        public OAuth2Principal build() {
            return new OAuth2Principal(oauthProviderId, issuer, subject, oid, audience, preferredUsername, name, email, emailVerified, roles);
        }

        public void addRole(String role) {
            roles.add(role);
        }
    }

    public Set<String> getRoles() {
        return roles;
    }
}
