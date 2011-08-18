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
package org.cesecore.mock.authentication;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.InvalidAuthenticationTokenException;
import org.cesecore.certificates.CertificateCreationException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;

/**
 * @see SimpleAuthenticationProvider
 * 
 * Based on cesecore version:
 *      SimpleAuthenticationProviderSessionBean.java 841 2011-05-19 14:14:29Z johane
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SimpleAuthenticationProviderRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SimpleAuthenticationProviderSessionBean implements SimpleAuthenticationProviderRemote, SimpleAuthenticationProviderLocal {

    private static final long serialVersionUID = -5788194519235705323L;

    static {
        CryptoProviderTools.installBCProvider();
    }

    /**
     * This is the pug of authentication; loves everybody.
     */
    @Override
    public AuthenticationToken authenticate(AuthenticationSubject subject) {
        KeyPair keys = null;
        try {
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAuthenticationTokenException("Could not create authentication token.", e);
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidAuthenticationTokenException("Could not create authentication token.", e);
        }

        /*
         * TODO: Document the bellow try/catch better.
         */
        String dn = "C=SE,O=Test,CN=Test"; // default
        // If we have created a subject with an X500Principal we will use this DN to create the dummy certificate.
        if (subject != null) {
        	Set<Principal> principals = subject.getPrincipals();
        	if ((principals != null) && (principals.size() > 0)) {
        		Principal p = principals.iterator().next();
        		if (p instanceof X500Principal) {
					X500Principal xp = (X500Principal)p;
					dn = xp.getName();
				}
        	}
        }
        X509Certificate certificate = null;
        try {
            certificate = CertTools.genSelfCert(dn, 365, null, keys.getPrivate(), keys.getPublic(),
                    AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        } catch (InvalidKeyException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CertificateEncodingException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (SignatureException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (IllegalStateException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (NoSuchProviderException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        }

        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        // We cannot use the X509CertificateAuthenticationToken here, since it can only be used internally in a JVM.
        AuthenticationToken result = new TestAuthenticationToken(principals, credentials);
        return result;
    }

}
