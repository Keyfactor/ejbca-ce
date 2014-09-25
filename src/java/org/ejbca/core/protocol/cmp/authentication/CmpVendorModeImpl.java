/*************************************************************************
 *                                                                       *
 *  EJBCA: Enterprise Certificate Authority                              *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.cmp.authentication;

import java.security.cert.Certificate;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.ejbca.config.CmpConfiguration;

/**
 * Check the authentication of the PKIMessage by verifying the signature from a Vendor CA (3GPP)
 * 
 * @version $Id$
 *
 */
public class CmpVendorModeImpl implements CmpVendorMode {

    private static final Logger log = Logger.getLogger(CmpVendorModeImpl.class);
    
    private CaSession caSession;
    private CmpConfiguration cmpConfiguration;

    @Override
    public void setCaSession(final CaSession caSession) {
        this.caSession = caSession;
    }

    @Override
    public void setCmpConfiguration(final CmpConfiguration cmpConfiguration) {
        this.cmpConfiguration = cmpConfiguration;
    }

    @Override
    public boolean isExtraCertIssuedByVendorCA(final AuthenticationToken admin, final String confAlias, final Certificate extraCert) {
        String vendorCAsStr = this.cmpConfiguration.getVendorCA(confAlias);
        String[] vendorcas = vendorCAsStr.split(";");
        CAInfo cainfo = null;
        for(String vendorca : vendorcas) {
            if(log.isDebugEnabled()) {
                log.debug("Checking if extraCert is issued by the VendorCA: " + vendorca);
            }
            
            try {
                cainfo = caSession.getCAInfo(admin, vendorca.trim());
                if(isExtraCertIssuedByCA(cainfo, extraCert)) {
                    return true;
                }
            } catch (CADoesntExistsException e) {
                if(log.isDebugEnabled()) {
                    log.debug("Cannot find CA: " + vendorca);
                }
            } catch (AuthorizationDeniedException e) {
                if(log.isDebugEnabled()) {
                    log.debug(e.getLocalizedMessage());
                }
            }
        }
        return false;
    }
    
    private boolean isExtraCertIssuedByCA(final CAInfo cainfo, final Certificate extraCert) {
        //Check that the extraCert is given by the right CA
        // Verify the signature of the client certificate as well, that it is really issued by this CA
        Certificate cacert = cainfo.getCertificateChain().iterator().next();
        try {
            extraCert.verify(cacert.getPublicKey(), "BC");
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                String errmsg = "The End Entity certificate attached to the PKIMessage is not issued by the CA '" + cainfo.getName() + "'";
                log.debug(errmsg + " - " + e.getLocalizedMessage());
            }
            return false;
        }
        return true;
    }

    /**
     * Checks whether authentication by vendor-issued-certificate should be used. It can be used only in client mode and with initialization/certification requests.
     *  
     * @param reqType
     * @return 'True' if authentication by vendor-issued-certificate is used. 'False' otherwise
     */
    @Override
    public boolean isVendorCertificateMode(final int reqType, final String confAlias) {
        return !this.cmpConfiguration.getRAMode(confAlias) && this.cmpConfiguration.getVendorMode(confAlias) && (reqType == 0 || reqType == 2);
    }

}
