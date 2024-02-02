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
package org.cesecore.authentication.oauth;

import java.io.Serializable;

/**
 * See <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0 incorporating errata set 2 section 5.3</a>.
 *
 */
public final class OAuthUserInfoResponse implements Serializable {
    private static final long serialVersionUID = 1L;

    private String subject;
    private String claims;
    private String responseString;
    
    public String getSubject() {
        return subject;
    }
    
    public void setSubject(final String subject) {
        this.subject = subject;
    }
    
    public String getClaims() {
        return claims;
    }
    
    public void setClaims(final String claims) {
        this.claims = claims;
    }
    
    public String getResponseString() {
        return responseString;
    }
    
    public void setResponseString(final String responseString) {
        this.responseString = responseString;
    }
    
}
