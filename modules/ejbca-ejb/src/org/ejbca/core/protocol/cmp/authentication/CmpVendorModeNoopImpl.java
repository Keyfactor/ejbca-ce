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

package org.ejbca.core.protocol.cmp.authentication;

import java.security.cert.X509Certificate;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.ejbca.config.CmpConfiguration;

/**
 * NoOperation implementation of CMP Vendor mode
 * 
 * @version $Id$
 *
 */
public class CmpVendorModeNoopImpl implements CmpVendorMode {

    @Override
    public void setCaSession(final CaSession caSession) {
    }

    @Override
    public void setCmpConfiguration(final CmpConfiguration cmpConfiguration) {
    }

    @Override
    public CAInfo isExtraCertIssuedByVendorCA(final AuthenticationToken admin, final String confAlias, final List<X509Certificate> extraCerts) {
        return null;
    }
    
    @Override
    public boolean isVendorCertificateMode(final int reqType, final String confAlias) {
        return false;
    }

}
