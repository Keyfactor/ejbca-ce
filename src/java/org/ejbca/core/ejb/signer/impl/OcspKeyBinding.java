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
package org.ejbca.core.ejb.signer.impl;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.signer.CertificateImportException;
import org.ejbca.core.ejb.signer.InternalKeyBindingBase;
import org.ejbca.core.ejb.signer.InternalKeyBindingProperty;

/**
 * Holder of "external" (e.g. non-CA signing key) OCSP InternalKeyBinding properties.
 * 
 * @version $Id$
 */
public class OcspKeyBinding extends InternalKeyBindingBase {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(OcspKeyBinding.class);

    private static final String PROPERTY_NON_EXISTING_GOOD = "nonExistingGood";
    private static final String PROPERTY_TRUSTED_CA_IDS = "trustedCaIds";
    
    @SuppressWarnings("serial")
    private static final List<InternalKeyBindingProperty<? extends Serializable>> PROPERTIES = new ArrayList<InternalKeyBindingProperty<? extends Serializable>>() {{
        add(new InternalKeyBindingProperty<Boolean>(PROPERTY_NON_EXISTING_GOOD, Boolean.FALSE));
        add(new InternalKeyBindingProperty<ArrayList<Integer>>(PROPERTY_TRUSTED_CA_IDS, new ArrayList<Integer>()));
    }};

    public OcspKeyBinding() {
        super(PROPERTIES);
    }
    
    @Override
    public String getImplementationAlias() {
        return "OcspKeyBinding";
    }
    
    @Override
    public float getLatestVersion() {
        return Long.valueOf(serialVersionUID).floatValue();
    }

    @Override
    protected void upgrade(float latestVersion, float currentVersion) {
        // Nothing to do
    }
    
    @Override
    public void assertCertificateCompatability(Certificate certificate) throws CertificateImportException {
        log.warn("CERTIFICATE VALIDATION HAS NOT BEEN IMPLEMENTED YET!");
    }

    public boolean getNonExistingGood() {
        return (Boolean) getProperty(PROPERTY_NON_EXISTING_GOOD).getValue();
    }
    public void setNonExistingGood(boolean nonExistingGood) {
        setProperty(PROPERTY_NON_EXISTING_GOOD, Boolean.valueOf(nonExistingGood));
    }
}
