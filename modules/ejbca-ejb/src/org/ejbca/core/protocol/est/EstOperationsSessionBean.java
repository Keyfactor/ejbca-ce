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

package org.ejbca.core.protocol.est;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.config.EstConfigurationCache;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Class that receives a EST message and passes it on to the correct message handler.
 * 
 * ----- 
 * This processes does the following: 
 * 1. receive a EST message 
 * 2. check which message type it is 
 * 3. dispatch to the correct message handler 
 * 4. send back the response received from the handler 
 * -----
 * 
 * Messages supported:
 * - Cacerts - will return the CA certificates for this profile
 * 
 * @version $Id: CmpMessageDispatcherSessionBean.java 26421 2017-08-25 08:52:59Z bastianf $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EstOperationsSessionRemote")
public class EstOperationsSessionBean implements EstOperationsSessionLocal, EstOperationsSessionRemote {
	private static final Logger log = Logger.getLogger(EstOperationsSessionBean.class);

	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
	
    @EJB
	private CertificateRequestSessionLocal certificateRequestSession;

    @EJB
    private CaSessionLocal caSession;

	@EJB
	private GlobalConfigurationSessionLocal globalConfigSession;

	@EJB
    private SignSessionLocal signSession;

	@EJB
	private EndEntityAccessSessionLocal endEntitySession;

	@EJB
	private EndEntityManagementSessionLocal endEntityManagementSession;
	
	@EJB
	private EndEntityProfileSessionLocal endEntityProfileSession;
	
	@EJB
	private CertificateProfileSessionLocal certProfileSession;

	@Override
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public byte[] getCacerts(AuthenticationToken authenticationToken, String estConfigurationAlias) throws NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException {
		EstConfiguration estConfig = (EstConfiguration) this.globalConfigSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
		if(!estConfig.aliasExists(estConfigurationAlias)) {
			throw new NoSuchAliasException("EST alias " + estConfigurationAlias + " does not exist");
		}

		// Get CA Certs from CA that we've configured for this alias
		final String caname = estConfig.getDefaultCA(estConfigurationAlias);
		log.debug("Got EST cacert request for CA '" + caname + "'.");
				  
		CAInfo cainfo = caSession.getCAInfo(authenticationToken, caname);
		byte[] pkcs7 = signSession.createPKCS7(authenticationToken, cainfo.getCAId(), true);
		return pkcs7;
	}

	@Override
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public byte[] simpleEnroll(AuthenticationToken authenticationToken, PKCS10RequestMessage req, String estConfigurationAlias) throws NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException {
		EstConfiguration estConfig = (EstConfiguration) this.globalConfigSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
		if(!estConfig.aliasExists(estConfigurationAlias)) {
			throw new NoSuchAliasException("EST alias " + estConfigurationAlias + " does not exist");
		}

		try {		
			// TODO: Check if users exists			
				
			// create user if needed
			int eeProfileId = 0;
			try {
				eeProfileId = Integer.parseInt(estConfig.getEndEntityProfile(estConfigurationAlias));
			} catch (NumberFormatException e) {
				log.error(e.getLocalizedMessage());
				return null;
			}
			int certProfileId = certProfileSession.getCertificateProfileId(estConfig.getCertProfile(estConfigurationAlias));
	
			final CAInfo caInfo = caSession.getCAInfo(authenticationToken, estConfig.getDefaultCA(estConfigurationAlias));
			
			final String dnname = req.getRequestDN();
			final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
			final String pwd = pwdgen.getNewPassword(12, 12);
			final String altNames = req.getRequestAltNames();
			final String email;
			final List<String> emails = CertTools.getEmailFromDN(altNames);
			emails.addAll(CertTools.getEmailFromDN(dnname.toString()));
			if (!emails.isEmpty()) {
				email = emails.get(0); // Use rfc822name or first SubjectDN email address as user email address if available
			} else {
				email = null;
			}
			
			final EndEntityInformation userdata = new EndEntityInformation(req.getUsername(), dnname.toString(), caInfo.getCAId(), altNames, email,
			EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), eeProfileId, certProfileId, null, null,
			SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
			userdata.setPassword(pwd);
			req.setPassword(pwd);
			endEntityManagementSession.addUser(authenticationToken, userdata, true);
			X509ResponseMessage resp = (X509ResponseMessage) signSession.createCertificate(authenticationToken, req, X509ResponseMessage.class, userdata);		 
			byte[] pkcs7 = signSession.createPKCS7(authenticationToken, (X509Certificate) resp.getCertificate(), true);
			return pkcs7;
		} catch (Exception e) {
			log.debug("oops: " + e);
			return null;
		}		
	}
}
