/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.types;

import java.util.ArrayList;
import java.util.List;

// TODO Javadoc
/**
 * A class representing general information about CA certificate.
 *
 * @version $Id: CaInfoType.java 28909 2018-05-10 12:16:53Z aminkh $
 */
public class CaInfoTypes {

    private List<CaInfoType> certificateAuthorities = new ArrayList<>();

    public CaInfoTypes() {
    }

    CaInfoTypes(final List<CaInfoType> certificateAuthorities) {
        this.certificateAuthorities = certificateAuthorities;
    }

    public List<CaInfoType> getCertificateAuthorities() {
        return certificateAuthorities;
    }

    public void setCertificateAuthorities(List<CaInfoType> certificateAuthorities) {
        this.certificateAuthorities = certificateAuthorities;
    }

    public static CaInfoTypesBuilder builder() {
        return new CaInfoTypesBuilder();
    }

    public static class CaInfoTypesBuilder {

        private List<CaInfoType> certificateAuthorities = new ArrayList<>();

        CaInfoTypesBuilder() {
        }

        public CaInfoTypesBuilder certificateAuthorities(final List<CaInfoType> certificateAuthorities) {
            this.certificateAuthorities = certificateAuthorities;
            return this;
        }

        public CaInfoTypes build() {
            return new CaInfoTypes(certificateAuthorities);
        }
    }
}
