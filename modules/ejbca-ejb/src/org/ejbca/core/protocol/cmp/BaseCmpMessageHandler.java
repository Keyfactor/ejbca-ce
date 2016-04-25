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

package org.ejbca.core.protocol.cmp;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.internal.InternalResources;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Base class for CMP message handlers that require RA mode secret verification.
 * 
 * This class contains common methods for extracting the RA authentication secret.
 * 
 * @version $Id$
 */
public class BaseCmpMessageHandler {

	private static Logger LOG = Logger.getLogger(BaseCmpMessageHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    /** strings for error messages defined in internal resources */
	protected static final String CMP_ERRORADDUSER = "cmp.erroradduser";
	protected static final String CMP_ERRORGENERAL = "cmp.errorgeneral";
	
	protected static final int CMP_GET_EEP_FROM_KEYID  = -1;
	protected static final int CMP_GET_CP_FROM_KEYID   = -1;
	protected static final int CMP_GET_CA_FROM_EEP     = -1;
	protected static final int CMP_GET_CA_FROM_KEYID   = -2;

	protected AuthenticationToken admin;
	protected String confAlias;
	protected CaSessionLocal caSession;
	protected EndEntityProfileSessionLocal endEntityProfileSession;
	protected CertificateProfileSession certificateProfileSession;
	protected CmpConfiguration cmpConfiguration;

	protected BaseCmpMessageHandler() {
	    this.confAlias = null;
	}

	protected BaseCmpMessageHandler(final AuthenticationToken admin, String configAlias, CaSessionLocal caSession, 
	                EndEntityProfileSessionLocal endEntityProfileSession, CertificateProfileSession certificateProfileSession, 
	                CmpConfiguration cmpConfig) {
		this.admin = admin;
		this.confAlias = configAlias;
		this.cmpConfiguration = cmpConfig;
		this.caSession = caSession;
		this.endEntityProfileSession = endEntityProfileSession;
		this.certificateProfileSession = certificateProfileSession;
	}

	/** @return the CA id to use for a request based on the current configuration, used end entity profile and keyId. 
	 * @throws AuthorizationDeniedException 
	 * @throws CADoesntExistsException */
	protected int getUsedCaId(final String keyId, final int eeProfileId) throws CADoesntExistsException, AuthorizationDeniedException {
		int ret = 0;
		final String caName = cmpConfiguration.getRACAName(this.confAlias);
		if (StringUtils.equals(caName, "ProfileDefault")) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Using default CA from End Entity Profile CA when adding users in RA mode.");
			}
			// get default CA id from end entity profile
			final EndEntityProfile eeProfile = endEntityProfileSession.getEndEntityProfileNoClone(eeProfileId);
			ret = eeProfile.getDefaultCA();
			if (ret == -1) {
				LOG.error("No default CA id for end entity profile: "+eeProfileId);
			} else {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Using CA with id: "+ret);
				}
			}
		} else if (StringUtils.equals(caName, "KeyId")) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Using keyId as CA name when adding users in RA mode: "+keyId);
			}
			if(keyId != null) {
			    // Use keyId as CA name
			    // No need to do access control here, just to get the CAId
			    final CAInfo info = caSession.getCAInfoInternal(-1, keyId, true);
			    if (LOG.isDebugEnabled()) {
			        LOG.debug("Using CA: "+info.getName());
			    }
			    ret = info.getCAId();
			} else {
			    LOG.error("Expecting the CA name to be specified in the KeyID parameter, but the KeyID parameter is 'null'");
			}
		} else {
            // No need to do access control here, just to get the CAId
            final CAInfo info = caSession.getCAInfoInternal(-1, caName, true);
			ret = info.getCAId();					
			if (LOG.isDebugEnabled()) {
				LOG.debug("Using fixed caName when adding users in RA mode: "+caName+"("+ret+")");
			}
		}
		return ret;
	}

	/** 
	 * @return the certificate profile name to use for a request based on the current configuration and keyId. 
	 */
	protected String getUsedCertProfileName(final String keyId, final int eeProfileId) throws NotFoundException {
	    // Get the configured string, may be a profile name or 'KeyId' or 'ProfileDefault'
		String certificateProfile = cmpConfiguration.getRACertProfile(this.confAlias);
		if (StringUtils.equals(certificateProfile, "ProfileDefault")) {
            // get default certificate profile id from end entity profile
            final EndEntityProfile eeProfile = endEntityProfileSession.getEndEntityProfileNoClone(eeProfileId);
            if (eeProfile == null) {
                final String msg = INTRES.getLocalizedMessage("store.errorcertprofilenotexist", eeProfileId);
                LOG.info(msg);
                throw new NotFoundException(msg);
            }
            certificateProfile = certificateProfileSession.getCertificateProfileName(eeProfile.getDefaultCertificateProfile());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using default certificate profile from End Entity Profile: " + certificateProfile);
            }
		} else if (StringUtils.equals(certificateProfile, "KeyId")) {
		    if(keyId != null) {
		        if (LOG.isDebugEnabled()) {
		            LOG.debug("Using Certificate Profile with same name as KeyId in request: " + keyId);
		        }
		        certificateProfile = keyId;
		    } else {
                LOG.error("Expecting the Certificate Profile name to be specified in the KeyID parameter, but the KeyID parameter is 'null'");
		    }
		}
		return certificateProfile;
	}
	/** @return the certificate profile to use for a request based on the current configuration and keyId. */
	protected int getUsedCertProfileId(final String certificateProfile) throws NotFoundException {
		final int ret = this.certificateProfileSession.getCertificateProfileId(certificateProfile);					
		if (ret == 0) {
			final String msg = "No certificate profile found with name: "+certificateProfile;
			LOG.info(msg);
			throw new NotFoundException(msg);
		}
		return ret;
	}
}
