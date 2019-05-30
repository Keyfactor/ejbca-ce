/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.response;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;

/**
 * A container class of CA information output.
 *
 * @version $Id: CaInfoRestResponse.java 28909 2018-05-22 12:16:53Z andrey_s_helmes $
 */
public class CaInfosRestResponse {

    private List<CaInfoRestResponse> certificateAuthorities = new ArrayList<>();

    /**
     * Simple constructor.
     */
    public CaInfosRestResponse() {
    }

    private CaInfosRestResponse(final List<CaInfoRestResponse> certificateAuthorities) {
        this.certificateAuthorities = certificateAuthorities;
    }

    /**
     * Returns the list of CaInfoRestResponse.
     *
     * @return list of CaInfoRestResponse.
     */
    public List<CaInfoRestResponse> getCertificateAuthorities() {
        return certificateAuthorities;
    }

    /**
     * Sets a list of CaInfoRestResponse.
     *
     * @param certificateAuthorities list of CaInfoRestResponse.
     */
    public void setCertificateAuthorities(List<CaInfoRestResponse> certificateAuthorities) {
        this.certificateAuthorities = certificateAuthorities;
    }

    /**
     * Returns a builder instance for this class.
     *
     * @return instance of builder for this class.
     */
    public static CaInfosRestResponseBuilder builder() {
        return new CaInfosRestResponseBuilder();
    }

    /**
     * Builder of this class.
     */
    public static class CaInfosRestResponseBuilder {

        private List<CaInfoRestResponse> certificateAuthorities = new ArrayList<>();

        CaInfosRestResponseBuilder() {
        }

        /**
         * Sets a list of CaInfoRestResponse in this builder.
         *
         * @param certificateAuthorities list of CaInfoRestResponse.
         *
         * @return instance of this builder.
         */
        public CaInfosRestResponseBuilder certificateAuthorities(final List<CaInfoRestResponse> certificateAuthorities) {
            this.certificateAuthorities = certificateAuthorities;
            return this;
        }

        /**
         * Builds an instance of CaInfosRestResponse using this builder.
         *
         * @return instance of CaInfosRestResponse using this builder.
         */
        public CaInfosRestResponse build() {
            return new CaInfosRestResponse(certificateAuthorities);
        }
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static CaInfosRestResponseConverter converter() {
        return new CaInfosRestResponseConverter();
    }

    /**
     * Converter of this class.
     */
    public static class CaInfosRestResponseConverter {

        CaInfosRestResponseConverter() {
        }

        /**
         * Converts a map of CAInfo into list of CaInfoRestResponse. Null-safe.
         *
         * @param caInfosMap input map of CAInfo.
         *
         * @return list of CaInfoRestResponse.
         */
        public List<CaInfoRestResponse> toRestResponses(final IdNameHashMap<CAInfo> caInfosMap) throws CADoesntExistsException {
            final List<CaInfoRestResponse> caInfoRestResponses = new ArrayList<>();
            if(caInfosMap != null && !caInfosMap.isEmpty()) {
                for(Map.Entry<Integer, KeyToValueHolder<CAInfo>> entry : caInfosMap.getIdMap().entrySet()) {
                    final KeyToValueHolder<CAInfo> caInfoKeyToValueHolder = entry.getValue();
                    caInfoRestResponses.add(CaInfoRestResponse.converter().toRestResponse(caInfoKeyToValueHolder.getValue()));
                }
            }
            return caInfoRestResponses;
        }

    }
}
