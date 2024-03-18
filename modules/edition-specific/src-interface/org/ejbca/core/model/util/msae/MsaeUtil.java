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
package org.ejbca.core.model.util.msae;

import java.util.Objects;

import org.ejbca.config.MSAutoEnrollmentConfiguration;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Class to hold MSAE related utility methods
 */
public final class MsaeUtil {

    private MsaeUtil() {
        //To avoid instantiation of utility class!
    }

    /**
     * Static util method to fetch the msae configuration from either local configuration cache or remote CA.
     * 
     * @param alias to fetch the configuration for 
     * @return msae enrollment config associated with the given alias (if any)
     */
    public static MSAutoEnrollmentConfiguration fetchMSAEConfig(String alias) {
        // First try local

        final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();

        MSAutoEnrollmentConfiguration msaeConfig = (MSAutoEnrollmentConfiguration) ejbLocalHelper.getGlobalConfigurationSession()
                .getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

        if (Objects.isNull(msaeConfig) || msaeConfig.getAliasList().isEmpty() || !msaeConfig.getAliasList().contains(alias)) {
            // Now we go for peers
            msaeConfig = ejbLocalHelper.getRaMasterApiProxyBean().getGlobalConfigurationLocalFirst(MSAutoEnrollmentConfiguration.class);
        }
        return msaeConfig;
    }

}
