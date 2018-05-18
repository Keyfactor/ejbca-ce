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

/**
 * A container class of CA information output.
 *
 * @version $Id: CaInfoType.java 28909 2018-05-10 12:16:53Z andrey_s_helmes $
 */
public class CaInfoTypes {

    private List<CaInfoType> certificateAuthorities = new ArrayList<>();

    /**
     * Simple constructor.
     */
    public CaInfoTypes() {
    }

    private CaInfoTypes(final List<CaInfoType> certificateAuthorities) {
        this.certificateAuthorities = certificateAuthorities;
    }

    /**
     * Returns the list of CaInfoType.
     *
     * @return list of CaInfoType.
     */
    public List<CaInfoType> getCertificateAuthorities() {
        return certificateAuthorities;
    }

    /**
     * Sets a list of CaInfoType.
     *
     * @param certificateAuthorities list of CaInfoType.
     */
    public void setCertificateAuthorities(List<CaInfoType> certificateAuthorities) {
        this.certificateAuthorities = certificateAuthorities;
    }

    /**
     * Returns a builder instance for this class.
     *
     * @return an instance of builder for this class.
     */
    public static CaInfoTypesBuilder builder() {
        return new CaInfoTypesBuilder();
    }

    /**
     * Builder of this class.
     */
    public static class CaInfoTypesBuilder {

        private List<CaInfoType> certificateAuthorities = new ArrayList<>();

        CaInfoTypesBuilder() {
        }

        /**
         * Sets a list of CaInfoType in this builder.
         *
         * @param certificateAuthorities list of CaInfoType.
         *
         * @return instance of this builder.
         */
        public CaInfoTypesBuilder certificateAuthorities(final List<CaInfoType> certificateAuthorities) {
            this.certificateAuthorities = certificateAuthorities;
            return this;
        }

        /**
         * Builds an instance of CaInfoTypes using this builder.
         *
         * @return instance of CaInfoTypes using this builder.
         */
        public CaInfoTypes build() {
            return new CaInfoTypes(certificateAuthorities);
        }
    }
}
