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
package org.cesecore.config;

import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 *
 */
public class GlobalOcspConfiguration extends ConfigurationBase {

    public static final String OCSP_CONFIGURATION_ID = "OCSP";
   
    private static final long serialVersionUID = 1L;

    private static final String DEFAULT_OCSP_RESPONDER_REFERENCE = "defaultOcspResponderReference";
    private static final String OCSP_RESPONDER_ID_TYPE_REFERENCE = "ocspResponderIdType";
    private static final String DEFAULT_NONCE_ENABLED_REFERENCE = "defaultNonceEnabled";
    
    public String getOcspDefaultResponderReference() {
        return CertTools.stringToBCDNString((String) data.get(DEFAULT_OCSP_RESPONDER_REFERENCE));
    }
    
    public void setOcspDefaultResponderReference(String reference) {
        data.put(DEFAULT_OCSP_RESPONDER_REFERENCE, reference);
    }
    
    @SuppressWarnings("deprecation")
    public OcspKeyBinding.ResponderIdType getOcspResponderIdType() {
        OcspKeyBinding.ResponderIdType ocspResponderIdType = (ResponderIdType) data.get(OCSP_RESPONDER_ID_TYPE_REFERENCE);
        if(ocspResponderIdType == null) {
            //Lazy upgrade if running from versions prior to 6.7.0
            ocspResponderIdType = OcspKeyBinding.ResponderIdType.getFromNumericValue(OcspConfiguration.getResponderIdType());
            setOcspResponderIdType(ocspResponderIdType);
        }
        return ocspResponderIdType;
    }
    
    public void setOcspResponderIdType(OcspKeyBinding.ResponderIdType ocspResponderIdType) {
        data.put(OCSP_RESPONDER_ID_TYPE_REFERENCE, ocspResponderIdType);
    }
    
    /**
     * 
     * @return true if CA's replying to their own OCSP requests should include NONCE's in the replies. 
     */
    public boolean getNonceEnabled() {
        //Lady upgrade
        if(data.get(DEFAULT_NONCE_ENABLED_REFERENCE) == null) {
            setNonceEnabled(true);
        }
        return (Boolean) data.get(DEFAULT_NONCE_ENABLED_REFERENCE);
    }
    
    /**
     * 
     * @param enabled to true if CA's replying to their own OCSP requests should include NONCE's in the replies. 
     */
    public void setNonceEnabled(boolean enabled) {
        data.put(DEFAULT_NONCE_ENABLED_REFERENCE, Boolean.valueOf(enabled));
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
