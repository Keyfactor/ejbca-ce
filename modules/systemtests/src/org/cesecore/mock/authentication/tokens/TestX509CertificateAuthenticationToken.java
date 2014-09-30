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
import java.util.Set;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

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
    
    private static final long serialVersionUID = 4343703249070152822L;

    private static final Pattern serialPattern = Pattern.compile("\\bSERIALNUMBER=", Pattern.CASE_INSENSITIVE);

    private final X509Certificate certificate;

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
    }

    @Override
    public boolean matches(AccessUserAspect accessUser) {
        // Protect against spoofing by checking if this token was created locally
        boolean returnvalue = false;

        String certstring = CertTools.getSubjectDN(certificate).toString();
        int adminCaId = CertTools.getIssuerDN(certificate).hashCode();

        certstring = serialPattern.matcher(certstring).replaceAll("SN=");

        String anString = null;

        anString = CertTools.getSubjectAlternativeName(certificate);

        int parameter;
        int size = 0;
        String[] clientstrings = null;

        // First check that issuers match.
        if (accessUser.getCaId() == adminCaId) {
            // Determine part of certificate to match with.
            DNFieldExtractor dn = new DNFieldExtractor(certstring, DNFieldExtractor.TYPE_SUBJECTDN);
            DNFieldExtractor an = new DNFieldExtractor(anString, DNFieldExtractor.TYPE_SUBJECTALTNAME);
            DNFieldExtractor usedExtractor = dn;
            X500PrincipalAccessMatchValue matchValue = (X500PrincipalAccessMatchValue) getMatchValueFromDatabaseValue(accessUser.getMatchWith());
            if (matchValue == X500PrincipalAccessMatchValue.WITH_SERIALNUMBER) {
                BigInteger matchValueAsBigInteger = new BigInteger(accessUser.getMatchValue(), 16);
                switch (accessUser.getMatchTypeAsType()) {
                case TYPE_EQUALCASE:
                case TYPE_EQUALCASEINS:
                    try {
                        returnvalue = matchValueAsBigInteger.equals(certificate.getSerialNumber());
                    } catch (NumberFormatException nfe) {
                    }
                    break;
                case TYPE_NOT_EQUALCASE:
                case TYPE_NOT_EQUALCASEINS:
                    try {
                        returnvalue = !matchValueAsBigInteger.equals(certificate.getSerialNumber());
                    } catch (NumberFormatException nfe) {
                    }
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
                    usedExtractor = an;
                    break;
                case WITH_UPN:
                    parameter = DNFieldExtractor.UPN;
                    usedExtractor = an;
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
