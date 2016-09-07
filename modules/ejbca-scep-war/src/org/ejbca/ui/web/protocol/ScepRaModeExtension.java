/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.protocol;

import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UsernameGenerator;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Enterprise plugin extension with the functionality for SCEP RA Mode. 
 * 
 * @version $Id$
 *
 */
public class ScepRaModeExtension implements ScepOperationPlugin {

    private static final Logger log = Logger.getLogger(ScepRaModeExtension.class);

    private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();

    public boolean performOperation(AuthenticationToken admin, ScepRequestMessage reqmsg, final ScepConfiguration scepConfig, final String alias) {

        final CaSessionLocal caSession = ejbLocalHelper.getCaSession();
        final CertificateProfileSessionLocal certProfileSession = ejbLocalHelper.getCertificateProfileSession();
        final CertificateStoreSessionLocal certificateStoreSession = ejbLocalHelper.getCertificateStoreSession();
        final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = ejbLocalHelper.getCryptoTokenManagementSession();
        final EndEntityProfileSessionLocal endEntityProfileSession = ejbLocalHelper.getEndEntityProfileSession();
        final EndEntityManagementSessionLocal endEntityManagementSession = ejbLocalHelper.getEndEntityManagementSession();
        final ScepConfiguration scepConfiguration = scepConfig;
        final String configAlias = alias;

        // Try to find the CA name from the issuerDN in the request. If we can't find it, we use the default
        String issuerDN = certificateStoreSession.getCADnFromRequest(reqmsg);
        String caName = null;
        try {
            caName = caSession.getCAInfoInternal(issuerDN.hashCode()).getName();
            if (log.isDebugEnabled()) {
                log.debug("Found a CA name '" + caName + "' from issuerDN: " + issuerDN);
            }
        } catch (CADoesntExistsException e) {
            caName = scepConfiguration.getRADefaultCA(configAlias);
            log.info("Did not find a CA name from issuerDN: " + issuerDN + ", using the default CA '" + caName + "'");
        }
        
        if (StringUtils.isEmpty(caName)) {
            log.error("No CA was set in the scep.propeties file.");
            return false;
        }

        CAInfo cainfo;
        CA ca;
        try {
            cainfo = caSession.getCAInfo(admin, caName);
            ca = caSession.getCA(admin, caName);
        } catch (CADoesntExistsException e1) {
            log.error("Could not find CA: " + caName);
            log.error(e1.getLocalizedMessage(), e1);
            return false;
        } catch (AuthorizationDeniedException e1) {
            log.error("Administator is not authorized for CA: " + caName);
            log.error(e1.getLocalizedMessage(), e1);
            return false;
        }
        final CAToken catoken = cainfo.getCAToken();
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
        try {
            reqmsg.setKeyInfo(ca.getCACertificate(), cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                    cryptoToken.getSignProviderName());
        } catch (CryptoTokenOfflineException e1) {
            log.error("Failed to set the new private key in the SCEP message");
            log.error(e1.getLocalizedMessage(), e1);
            return false;
        }

        // Verify the request
        String authPwd = scepConfiguration.getRAAuthPassword(configAlias);
        if (StringUtils.isNotEmpty(authPwd) && !StringUtils.equals(authPwd, "none")) {
            if (log.isDebugEnabled()) {
                log.debug("Requiring authPwd in order to precess SCEP requests");
            }
            String pwd = reqmsg.getPassword();
            if (!StringUtils.equals(authPwd, pwd)) {
                log.error("Wrong auth password received in SCEP request: " + pwd);
                return false;
            }
            if (log.isDebugEnabled()) {
                log.debug("Request passed authPwd test.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Not requiring authPwd in order to precess SCEP requests");
            }
        }

        //Creating the user
        UsernameGeneratorParams usernameGenParams = new UsernameGeneratorParams();
        usernameGenParams.setMode(scepConfiguration.getRANameGenerationScheme(configAlias));
        usernameGenParams.setDNGeneratorComponent(scepConfiguration.getRANameGenerationParameters(configAlias));
        usernameGenParams.setPrefix(scepConfiguration.getRANameGenerationPrefix(configAlias));
        usernameGenParams.setPostfix(scepConfiguration.getRANameGenerationPostfix(configAlias));

        X500Name dnname = new X500Name(reqmsg.getRequestDN());
        final UsernameGenerator gen = UsernameGenerator.getInstance(usernameGenParams);
        final String username = gen.generateUsername(dnname.toString());
        final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
        final String pwd = pwdgen.getNewPassword(12, 12);

        // AltNames may be in the request template
        final String altNames = reqmsg.getRequestAltNames();
        final String email;
        final List<String> emails = CertTools.getEmailFromDN(altNames);
        emails.addAll(CertTools.getEmailFromDN(dnname.toString()));
        if (!emails.isEmpty()) {
            email = emails.get(0); // Use rfc822name or first SubjectDN email address as user email address if available
        } else {
            email = null;
        }

        int eeProfileId = 0;
        try {
            eeProfileId = endEntityProfileSession.getEndEntityProfileId(scepConfiguration.getRAEndEntityProfile(configAlias));
        } catch (EndEntityProfileNotFoundException e) {
            log.error("Could not find the end entity profile: " + scepConfiguration.getRAEndEntityProfile(configAlias));
            log.error(e.getLocalizedMessage(), e);
            return false;
        }
        int certProfileId = certProfileSession.getCertificateProfileId(scepConfiguration.getRACertProfile(configAlias));

        final EndEntityInformation userdata = new EndEntityInformation(username, dnname.toString(), cainfo.getCAId(), altNames, email,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), eeProfileId, certProfileId, null, null,
                SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        userdata.setPassword(pwd);
        reqmsg.setUsername(username);
        reqmsg.setPassword(pwd);

        try {
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.changeUser(admin, userdata, true);
                endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
            } else {
                endEntityManagementSession.addUser(admin, userdata, true);
            }
        } catch (Exception e) {
            log.error("Failed to add or edit user: " + username);
            log.error(e.getLocalizedMessage(), e);
            return false;
        }

        return true;
    }

}
