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
package org.cesecore.certificates.ca.extendedservices;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.HashMap;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.CryptoToken;

/**
 * ExtendedCAService base class. An implementing class MUST have a constructor taking a ExtendedCAServiceInfo as argument.
 * 
 * @version $Id$
 */
public abstract class ExtendedCAService extends UpgradeableDataHashMap implements java.io.Serializable {

    private static final long serialVersionUID = 4014122870575602909L;

    public static final String EXTENDEDCASERVICETYPE = "extendedcaservicetype";

    public final String SERVICENAME = "";

    public static final String STATUS = "status";

    /** The CA that the request can be enriched with, in order to let the extended service access CA key, certificates etc */
    private transient CA ca;

    // Overriding classes needs this constructor
    public ExtendedCAService(ExtendedCAServiceInfo info) {
    }
    
    // Overriding classes needs this constructor
    public ExtendedCAService(HashMap<?, ?> data) {
    }

    protected void setStatus(int status) {
        this.data.put(STATUS, Integer.valueOf(status));
    }

    protected int getStatus() {
        return ((Integer) data.get(STATUS)).intValue();
    }

    /**
     * Method called by the CA before using the service with #extendedService. Used to (temporarily) give the service access to CA keys, certificates
     * etc that might be needed for the service to run perform its service.
     * 
     * @param ca
     *            the CA from which the service can use private keys to generate service certificates etc.
     */
    public final void setCA(final CA ca) {
        this.ca = ca;
    }

    public final CA getCa() {
        return ca;
    }

    /**
     * Initializes the ExtendedCAService the first time it is created. Only used when the CA service is created the first time, usually this is when
     * the CA is created, or the service of the CA is renewed.
     * 
     * @param ca the CA from which the service can use private keys to generate service certificates etc. This must not be stored.
     * @param cceConfig containing a list of available custom certificate extensions
     */
    public abstract void init(final CryptoToken cryptoToken, CA ca, AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception;

    /**
     * Update the ExtendedCAService data
     * 
     * @param info
     *            contains information used to activate the service.
     */
    public abstract void update(final CryptoToken cryptoToken, ExtendedCAServiceInfo info, CA ca, AvailableCustomCertificateExtensionsConfiguration cceConfig);

    /**
     * Method used to retrieve information about the service.
     */

    public abstract ExtendedCAServiceInfo getExtendedCAServiceInfo();

    /**
     * Method used to perform the service.
     * @throws OperatorCreationException 
     * @throws CertificateException 
     * @throws CertificateEncodingException 
     */
    public abstract ExtendedCAServiceResponse extendedService(final CryptoToken cryptoToken, ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException,
            IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, CertificateEncodingException, CertificateException, OperatorCreationException;

}
