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
package org.ejbca.core.ejb.ca.publisher;

import java.security.cert.Certificate;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 * Mock publisher that will make n successful attempts to publish and then return failures, leading to a mixed result if required.
 * 
 * @version $Id$
 *
 */
public class MockPublisher extends CustomPublisherContainer implements ICustomPublisher {

    private static final long serialVersionUID = 1L;
    
    public static final String PROPERTYKEY_LIMIT = "successLimit";
    public static final String PROPERTYKEY_SUCCESSES = "numberOfSuccesses";
    
    private int successLimit;
    
    public MockPublisher() {
        super();
        setClassPath(this.getClass().getName());
        data.put(PROPERTYKEY_SUCCESSES, 0);
        
    }
    
    public MockPublisher(Properties properties) {
        init(properties);
    }

    @Override
    public boolean storeCertificate(AuthenticationToken authenticationToken, Certificate certificate, String usernameParam, String password, String issuerDn, String caFingerprint,
            int statusParam, int typeParam, long revocationDateParam, int revocationReasonParam, String tagParam, int certificateProfileIdParam, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        int numberOfSuccesses = (int) data.get(PROPERTYKEY_SUCCESSES);
        numberOfSuccesses++;
        data.put(PROPERTYKEY_SUCCESSES, numberOfSuccesses);
        return numberOfSuccesses <= successLimit;
    }
    
    @Override
    public void init(Properties properties) {
        successLimit = Integer.parseInt(properties.getProperty(PROPERTYKEY_LIMIT));
        data.put(PROPERTYKEY_LIMIT, successLimit);
        if(!data.containsKey(PROPERTYKEY_SUCCESSES)) {
            data.put(PROPERTYKEY_SUCCESSES, 0);
        }
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }


}
