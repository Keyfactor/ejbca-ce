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
package org.cesecore.mock.authentication.tokens;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.InvalidAuthenticationTokenException;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.CertTools;

/**
 * Acts like X509CertificateAuthenticationToken, but without the JVM-only check. 
 * 
 * @version $Id$
 */

public class TestX509CertificateAuthenticationToken extends X509CertificateAuthenticationToken {

    public static final String TOKEN_TYPE = X509CertificateAuthenticationToken.TOKEN_TYPE;
    
    private static final Logger log = Logger.getLogger(X509CertificateAuthenticationToken.class);
    
    private static final long serialVersionUID = 4343703249070152822L;

    private static final Pattern serialPattern = Pattern.compile("\\bSERIALNUMBER=", Pattern.CASE_INSENSITIVE);
    
    private final X509Certificate certificate;
    private final int adminCaId;    
    private final DNFieldExtractor dnExtractor;
    private final DNFieldExtractor anExtractor;

    public TestX509CertificateAuthenticationToken(Set<X500Principal> principals, Set<X509Certificate> credentials) {
        super(principals, credentials);
        /*
         * In order to save having to verify the credentials set every time the <code>matches(...)</code> method is called, it's checked here, and the
         * resulting credential is stored locally.
         */
        X509Certificate[] certificateArray = getCredentials().toArray(new X509Certificate[0]);
        if (certificateArray.length != 1) {
            throw new InvalidAuthenticationTokenException("X509CertificateAuthenticationToken was containing " + certificateArray.length
                    + " credentials instead of 1.");
        } else {
            certificate = certificateArray[0];
        }
        adminCaId = CertTools.getIssuerDN(certificate).hashCode();
        String certstring = CertTools.getSubjectDN(certificate).toString();
        certstring = serialPattern.matcher(certstring).replaceAll("SN=");
        String altNameString = CertTools.getSubjectAlternativeName(certificate);

        dnExtractor = new DNFieldExtractor(certstring, DNFieldExtractor.TYPE_SUBJECTDN);       
        anExtractor = new DNFieldExtractor(altNameString, DNFieldExtractor.TYPE_SUBJECTALTNAME);

    }

    /**
     * Standard simplified constructor for X509CertificateAuthenticationToken
     * 
     * @param certificate A X509Certificate that will be used as principal and credential.
     * @throws NullPointerException if the provided certificate is null
     */
    public TestX509CertificateAuthenticationToken(final X509Certificate certificate) {
        this(new HashSet<>(Arrays.asList(new X500Principal[]{ certificate.getSubjectX500Principal() })),
                new HashSet<>(Arrays.asList(new X509Certificate[]{ certificate })));
    }

    @Override
    public boolean matches(AccessUserAspect accessUser) {
        boolean returnvalue = false;

        int parameter;
        int size = 0;
        String[] clientstrings = null;
        if (StringUtils.equals(TOKEN_TYPE,accessUser.getTokenType())) {
            // First check that issuers match.
            if (accessUser.getCaId() == adminCaId) {
                // Determine part of certificate to match with.
                DNFieldExtractor usedExtractor = dnExtractor;
                X500PrincipalAccessMatchValue matchValue = (X500PrincipalAccessMatchValue) getMatchValueFromDatabaseValue(accessUser.getMatchWith());
                if (matchValue == X500PrincipalAccessMatchValue.WITH_SERIALNUMBER) {
                    try {
                    BigInteger matchValueAsBigInteger = new BigInteger(accessUser.getMatchValue(), 16);
                        switch (accessUser.getMatchTypeAsType()) {
                        case TYPE_EQUALCASE:
                        case TYPE_EQUALCASEINS:
                            returnvalue = matchValueAsBigInteger.equals(certificate.getSerialNumber());
                            break;
                        case TYPE_NOT_EQUALCASE:
                        case TYPE_NOT_EQUALCASEINS:
                            returnvalue = !matchValueAsBigInteger.equals(certificate.getSerialNumber());
                            break;
                        default:
                        }
                    } catch (NumberFormatException nfe) {
                        log.info("Invalid matchValue for accessUser when expecting a hex serialNumber: "+accessUser.getMatchValue());
                    }
                } else if (matchValue == X500PrincipalAccessMatchValue.WITH_FULLDN) {
                    String value = accessUser.getMatchValue();
                    switch (accessUser.getMatchTypeAsType()) {
                    case TYPE_EQUALCASE:
                        returnvalue = value.equals(CertTools.getSubjectDN(certificate));
                    case TYPE_EQUALCASEINS:
                        returnvalue = value.equalsIgnoreCase(CertTools.getSubjectDN(certificate));
                        break;
                    case TYPE_NOT_EQUALCASE:
                        returnvalue = !value.equals(CertTools.getSubjectDN(certificate));
                    case TYPE_NOT_EQUALCASEINS:
                        returnvalue = !value.equalsIgnoreCase(CertTools.getSubjectDN(certificate));
                        break;
                    default:
                    }
                } else {
                    parameter = DNFieldExtractor.CN;
                    switch (matchValue) {
                    case WITH_COUNTRY:
                        parameter = DNFieldExtractor.C;
                        break;
                    case WITH_DOMAINCOMPONENT:
                        parameter = DNFieldExtractor.DC;
                        break;
                    case WITH_STATEORPROVINCE:
                        parameter = DNFieldExtractor.ST;
                        break;
                    case WITH_LOCALITY:
                        parameter = DNFieldExtractor.L;
                        break;
                    case WITH_ORGANIZATION:
                        parameter = DNFieldExtractor.O;
                        break;
                    case WITH_ORGANIZATIONALUNIT:
                        parameter = DNFieldExtractor.OU;
                        break;
                    case WITH_TITLE:
                        parameter = DNFieldExtractor.T;
                        break;
                    case WITH_DNSERIALNUMBER:
                        parameter = DNFieldExtractor.SN;
                        break;
                    case WITH_COMMONNAME:
                        parameter = DNFieldExtractor.CN;
                        break;
                    case WITH_UID:
                        parameter = DNFieldExtractor.UID;
                        break;
                    case WITH_DNEMAILADDRESS:
                        parameter = DNFieldExtractor.E;
                        break;
                    case WITH_RFC822NAME:
                        parameter = DNFieldExtractor.RFC822NAME;
                        usedExtractor = anExtractor;
                        break;
                    case WITH_UPN:
                        parameter = DNFieldExtractor.UPN;
                        usedExtractor = anExtractor;
                        break;
                    default:
                    }
                    size = usedExtractor.getNumberOfFields(parameter);
                    clientstrings = new String[size];
                    for (int i = 0; i < size; i++) {
                        clientstrings[i] = usedExtractor.getField(parameter, i);
                    }

                    // Determine how to match.
                    if (clientstrings != null) {
                        switch (accessUser.getMatchTypeAsType()) {
                        case TYPE_EQUALCASE:
                            for (int i = 0; i < size; i++) {
                                returnvalue = clientstrings[i].equals(accessUser.getMatchValue());
                                if (returnvalue) {
                                    break;
                                }
                            }
                            break;
                        case TYPE_EQUALCASEINS:
                            for (int i = 0; i < size; i++) {
                                returnvalue = clientstrings[i].equalsIgnoreCase(accessUser.getMatchValue());
                                if (returnvalue) {
                                    break;
                                }
                            }
                            break;
                        case TYPE_NOT_EQUALCASE:
                            for (int i = 0; i < size; i++) {
                                returnvalue = !clientstrings[i].equals(accessUser.getMatchValue());
                                if (returnvalue) {
                                    break;
                                }
                            }
                            break;
                        case TYPE_NOT_EQUALCASEINS:
                            for (int i = 0; i < size; i++) {
                                returnvalue = !clientstrings[i].equalsIgnoreCase(accessUser.getMatchValue());
                                if (returnvalue) {
                                    break;
                                }
                            }
                            break;
                        default:
                        }
                    }
                }
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("Caid does not match. Required="+adminCaId+", actual was "+accessUser.getCaId());
                }
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Token type does not match. Required="+TOKEN_TYPE+", actual was "+accessUser.getTokenType());
            }            
        }

        return returnvalue;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        TestX509CertificateAuthenticationToken other = (TestX509CertificateAuthenticationToken) obj;
        if (certificate == null) {
            if (other.certificate != null) {
                return false;
            }
        } else if (!certificate.equals(other.certificate)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 4711;
        int result = 1;
        result = (int) (prime * result + ((certificate == null) ? 0 : certificate.hashCode()) + serialVersionUID);
        return result;
    }
    
    public X509Certificate getCertificate() {
        return this.certificate;
    }

    @Override
    public boolean matchTokenType(String tokenType) {
        return tokenType.equals(X509CertificateAuthenticationToken.TOKEN_TYPE);
    }

    @Override
    public AccessMatchValue getDefaultMatchValue() {        
        return X500PrincipalAccessMatchValue.NONE;
    }
    
    @Override
    public AccessMatchValue getMatchValueFromDatabaseValue(Integer databaseValue) {
        return AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(TOKEN_TYPE, databaseValue.intValue());
    }
}
