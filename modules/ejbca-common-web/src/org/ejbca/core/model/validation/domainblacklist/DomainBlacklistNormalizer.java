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
package org.ejbca.core.model.validation.domainblacklist;

import java.util.Map;

import org.cesecore.util.NameTranslatable;

/**
 * Domain Blacklist Normalizers normalizes domain names, such that both (for example)
 * "normalization.com" and "n0rrna1ization.com" are considered equal.
 * Domain Blacklist Normalizers are intended to be cached (in a DomainBlacklistValidator) and re-used.
 *
 * @version $Id$
 */
public interface DomainBlacklistNormalizer extends NameTranslatable /*extends DynamicUiModelAware*/ {

    /**
     * Initializes this blacklist normalizer.
     * @param configData Data hash map with configuration options (if the normalizer is configurable)
     */
    void initialize(final Map<Object,Object> configData);

    /**
     * Normalizes a domain name, for example "examp1e.com" might be transformed to "example.com"
     * @param configData Data hash map with configuration options (if the normalizer is configurable)
     * @param domain
     * @return Normalized domain name
     */
    String normalize(final String domain);

    // TODO configurable normalizers (ECA-6052). might not be needed for 7.0.1
//    /**
//     * Adds configuration controls needed for this normalizer.
//     * @param uiModel
//     */
//    void addToUiModel(final Map<String,Object> data, final DynamicUiModel uiModel);
}
