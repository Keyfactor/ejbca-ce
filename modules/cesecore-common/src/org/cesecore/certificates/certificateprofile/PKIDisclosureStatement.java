/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificateprofile;

import java.io.Serializable;

import org.apache.commons.lang.StringUtils;

/**
 * Contains a single URI/language pair of a PKI disclosure statement. 
 * @version $Id$
 */
public final class PKIDisclosureStatement implements Serializable, Cloneable {
    
    private static final long serialVersionUID = 1L;
    
    private String url;
    private String language;
    
    public PKIDisclosureStatement(final String url, final String language) {
        this.url = url;
        this.language = language;
    }

    /** @return String with PDS URL. Never null */
    public String getUrl() {
        return url;
    }

    /** Sets the PDS URL (EN 319 412-05) */
    public void setUrl(final String url) {
        this.url = url;
    }

    /** Shall be a two letter ISO 639-1 code, i.e. en, sv, fr  
     * @return String with PDS Language or empty string (EN 319 412-05) 
     */
    public String getLanguage() {
        return language;
    }

    /** Sets String with PDS Language (EN 319 412-05) 
     * Shall be a two letter ISO 639-1 code, i.e. en, sv, fr 
     */
    public void setLanguage(final String language) {
        this.language = language;
    }
    
    @Override
    public boolean equals(final Object other) {
        if (other instanceof PKIDisclosureStatement) {
            final PKIDisclosureStatement o = (PKIDisclosureStatement) other;
            return StringUtils.equals(url, o.getUrl()) && StringUtils.equals(language, o.getLanguage());
        } else {
            return false;
        }
    }
    
    @Override
    public int hashCode() {
        return url.hashCode() ^ language.hashCode();
    }
    
    @Override
    protected Object clone() throws CloneNotSupportedException {
        return new PKIDisclosureStatement(url, language);
    }
    
    @Override
    public String toString() {
        return "{" + language + "}" + url;
    }
    
}
