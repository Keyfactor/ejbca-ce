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
package org.cesecore.config;

import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 *
 */
public class GlobalOcspConfiguration extends ConfigurationBase {

    public static final String OCSP_CONFIGURATION_ID = "3";
   
    private static final long serialVersionUID = 1L;

    private static final String DEFAULT_OCSP_RESPONDER_REFERENCE = "defaultOcspResponderReference";
    
    public String getOcspDefaultResponderReference() {
        return CertTools.stringToBCDNString((String) data.get(DEFAULT_OCSP_RESPONDER_REFERENCE));
    }
    
    public void setOcspDefaultResponderReference(String reference) {
        data.put(DEFAULT_OCSP_RESPONDER_REFERENCE, reference);
    }
    
    
    @Override
    public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));          
        }
    }

    @Override
    public String getConfigurationId() {
        return OCSP_CONFIGURATION_ID;
    }

}
