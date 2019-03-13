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
package org.cesecore.certificates.util.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * A class for reading values from CRL extensions.
 *
 * @version $Id$
 */
public class CrlExtensions {
    private static Logger log = Logger.getLogger(CrlExtensions.class);

    /** Returns the CRL number if it exists as a CRL extension
     * 
     * @return the CRLnumber, or 0 if no CRL number extension was found or an error reading it occurred. Never return null.
     */
    public static BigInteger getCrlNumber(X509CRL crl) {
    	BigInteger ret = BigInteger.valueOf(0);
        try {
			ASN1Primitive obj = CrlExtensions.getExtensionValue(crl, Extension.cRLNumber.getId());
			if (obj != null) {
				CRLNumber crlnum = CRLNumber.getInstance(obj);
				if (crlnum != null) {
					ret = crlnum.getCRLNumber();
				}
			}
		} catch (IOException e) {
			log.error("Error reading CRL number extension: ", e);
		}
		return ret;
    }

    /** Returns the delta crl indicator number if it exists as a CRL extension
     * 
     * @return the BaseCRLNumber, or -1 if no delta crl indicator extension was found or an error reading it occurred. Never return null.
     */
    public static BigInteger getDeltaCRLIndicator(X509CRL crl) {
    	BigInteger ret = BigInteger.valueOf(-1);
        try {
			ASN1Primitive obj = CrlExtensions.getExtensionValue(crl, Extension.deltaCRLIndicator.getId());
			if (obj != null) {
			    CRLNumber crlnum = CRLNumber.getInstance(obj);
	            if (crlnum != null) {
	                ret = crlnum.getCRLNumber();            	
	            }				
			}
		} catch (IOException e) {
			log.error("Error reading CRL number extension: ", e);
		}
		return ret;
    }

    /**
     * Return an Extension ASN1Primitive from a CRL
     */
    protected static ASN1Primitive getExtensionValue(X509CRL crl, String oid)
      throws IOException {
    	if (crl == null) {
    		return null;
    	}
        byte[] bytes = crl.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    } //getExtensionValue

    /** @return the revocation reason code as defined in RevokedCertInfo.REVOCATION_REASON_... */
    public static int extractReasonCode(final X509CRLEntry crlEntry) {
        int reasonCode = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
        if (crlEntry.hasExtensions()) {
            final byte[] extensionValue = crlEntry.getExtensionValue(Extension.reasonCode.getId());
            if (extensionValue!=null) {
                try {
                    final ASN1Enumerated reasonCodeExtension = ASN1Enumerated.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue));
                    if (reasonCodeExtension!=null) {
                        reasonCode = reasonCodeExtension.getValue().intValue();
                    }
                } catch (IOException e) {
                    log.debug("Failed to parse reason code of CRLEntry: " + e.getMessage());
                }
            }
        }
        return reasonCode;
    }

    /** @return a list of URLs in String format with present freshest CRL extensions or an empty List */
    public static List<String> extractFreshestCrlDistributionPoints(final X509CRL crl) {
        final List<String> freshestCdpUrls = new ArrayList<String>();
        final byte[] extensionValue = crl.getExtensionValue(Extension.freshestCRL.getId());
        if (extensionValue!=null) {
            final ASN1OctetString asn1OctetString = getAsn1ObjectFromBytes(extensionValue, ASN1OctetString.class);
            if (asn1OctetString!=null) {
                final ASN1Sequence asn1Sequence = getAsn1ObjectFromBytes(asn1OctetString.getOctets(), ASN1Sequence.class);
                if (asn1Sequence!=null) {
                    final CRLDistPoint cdp = CRLDistPoint.getInstance(asn1Sequence);
                    for (final DistributionPoint distributionPoint : cdp.getDistributionPoints()) {
                        freshestCdpUrls.add(((DERIA5String) ((GeneralNames) distributionPoint.getDistributionPoint().getName()).getNames()[0].getName()).getString());
                    }
                }
            }
        }
        return freshestCdpUrls;
    }
    
    /** @return the first object found when treating the provided byte array as an ASN1InputStream */
    @SuppressWarnings("unchecked")
    private static <T> T getAsn1ObjectFromBytes(final byte[] bytes, final Class<T> clazz) {
        T ret = null;
        ASN1InputStream asn1InputStream = null;
        try {
            if (bytes!=null) {
                asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(bytes));
                ret = (T) asn1InputStream.readObject();
            }
        } catch (ClassCastException e) {
            // Ignore
            log.info("Failed to extract expected ASN1 object from bytes array.", e);
        } catch (IOException e) {
            // Ignore
            log.info("Failed to extract ASN1 object from bytes array.", e);
        } finally {
            if (asn1InputStream!=null) {
                try {
                    asn1InputStream.close();
                } catch (IOException e) {
                    log.info("Failed to extract expected ASN1 object from bytes array.", e);
                }
            }
        }
        return ret;
    }
}
