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

package org.ejbca.core.protocol.unid;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.cesecore.certificates.ca.ExtendedUserDataHandler;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.unidfnr.UnidfnrSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.protocol.cmp.ICrmfRequestMessage;
import org.ejbca.util.passgen.LettersAndDigitsPasswordGenerator;

import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;

/**
 * FNR is the Norwegian equivalent of a SSN or personal number, i.e, a unique numerical identifier for a Norwegian national. Norwegian regulation 
 * requires that the FNR is not unduly exposed, so hence during enrollment the FNR is replaced in the request with a generated unique ID (UnID), 
 * which will be used as reference for future OCSP requests, which for this purpose will contain the UnID as opposed to the FNR as an extension
 * in the response. 
 * 
 * @version $Id$
 */
public class UnidFnrHandler implements ExtendedUserDataHandler {
	private static final long serialVersionUID = 1L;
    private static final Logger LOG = Logger.getLogger(UnidFnrHandler.class);
	private static final Pattern onlyDecimalDigits = Pattern.compile("^[0-9]+$");
	protected UnidfnrSessionLocal unidfnrSession;

	public UnidFnrHandler() {
		super();
		unidfnrSession = new EjbLocalHelper().getUnidfnrSession();
	}

	
	@Override
	public RequestMessage processRequestMessage(RequestMessage req, final String certificateProfileName) {
	    final X500Name dn = req.getRequestX500Name();
	    if (LOG.isDebugEnabled()) {
			LOG.debug(">processRequestMessage:'"+dn+"' and '"+certificateProfileName+"'");
		}
		final String unidPrefix = getPrefixFromCertProfileName(certificateProfileName);
		if ( unidPrefix==null ) {
			return req;
		}
		X500Name modifiedDN = getModifiedX500Name(unidPrefix, dn);
	
        if (modifiedDN != null) {
            if (req instanceof ICrmfRequestMessage) {
                return new CrmfRequestDnAdapter(req, modifiedDN);
            } else if (req instanceof PKCS10RequestMessage) {
                return new Pkcs10RequestDnAdapter(req, modifiedDN);
            } else {
                //SCEP messages won't find their way here
                throw new IllegalStateException("Unknown message type encountered.");
            }
        } else {
            return req;
        }
	}
	
    @Override
    public EndEntityInformation processEndEntityInformation(final EndEntityInformation endEntityInformation, final String certificateProfileName) {
        //Create a safe copy to work on
        EndEntityInformation result = new EndEntityInformation(endEntityInformation);
        final String unidPrefix = getPrefixFromCertProfileName(certificateProfileName);
        if ( unidPrefix==null ) {
            LOG.debug("Certificate profile " + certificateProfileName + " was not named correctly for UnidFNR operations.");
            return result;
        } else {
            X500Name modifiedDN = getModifiedX500Name(unidPrefix, CertTools.stringToBcX500Name(endEntityInformation.getDN()));
            if(modifiedDN != null) {
                result.setDN(modifiedDN.toString());
            } 
            return result;       
        }
    }
    
    /**
     * Modifies the DN by replacing serialNumber vales with the UnidFNR equivalents
     * 
     * @param dn the DN to examine
     * @return the modified DN or null if no changes were made
     */
    private X500Name getModifiedX500Name(final String unidPrefix, final X500Name dn) {
        final List<ASN1ObjectIdentifier> asn1ObjectIdentifiers = Arrays.asList(dn.getAttributeTypes());
        X500NameBuilder nameBuilder = new X500NameBuilder(new CeSecoreNameStyle());
        boolean changed = false;
        for (final ASN1ObjectIdentifier asn1ObjectIdentifier : asn1ObjectIdentifiers) {
            if (asn1ObjectIdentifier.equals(CeSecoreNameStyle.SERIALNUMBER) ) {
                RDN[] rdns = dn.getRDNs(asn1ObjectIdentifier);
                String value = rdns[0].getFirst().getValue().toString();
                final String newSerial = storeUnidFrnAndGetNewSerialNr(value, unidPrefix);
                if ( newSerial!=null ) {
                    nameBuilder.addRDN(asn1ObjectIdentifier, newSerial);
                    changed = true;
                }
            } else {
                nameBuilder.addRDN(dn.getRDNs(asn1ObjectIdentifier)[0].getFirst());
            }
        }
        if (changed) {
            return nameBuilder.build();
        } else {
            return null;
        }
    }
	
	private static boolean hasOnlyDecimalDigits(String s, int first, int last) {
		return hasOnlyDecimalDigits(s.substring(first, last));
	}
	
	private static boolean hasOnlyDecimalDigits(String s) {
		return onlyDecimalDigits.matcher(s).matches();
	}
	
	private String getPrefixFromCertProfileName(String certificateProfileName) {
		if ( certificateProfileName.length()<10 ) {
			return null;
		}
		if ( certificateProfileName.charAt(4)!='-' ) {
			return null;
		}
		if ( certificateProfileName.charAt(9)!='-' ) {
			return null;
		}
		if ( !hasOnlyDecimalDigits(certificateProfileName, 0, 4) ) {
			return null;
		}
		if ( !hasOnlyDecimalDigits(certificateProfileName, 5, 9) ) {
			return null;
		}
		return certificateProfileName.substring(0, 10);
	}
	/**
	 * @param inputSerialNr SN of subject DN in the incoming request
	 * @param unidPrefix Prefix of the unid
	 * @return the serial number of the subject DN of the certificate that will be created. Null if the format of the SN is not fnr-lra.
	 * Returning null means that the handler should not do anything (SN in DN not changed and nothing stored to DB).
	 */
	private String storeUnidFrnAndGetNewSerialNr(final String inputSerialNr, final String unidPrefix) {
	    	   
		if ( inputSerialNr.length()!=17 ) {
			return null;
		}
		if ( inputSerialNr.charAt(11)!='-' ) {
			return null;
		}
		final String fnr = inputSerialNr.substring(0, 11);
		if ( !hasOnlyDecimalDigits(fnr) ) {
			return null;
		}
		final String lra = inputSerialNr.substring(12);
		if ( !hasOnlyDecimalDigits(lra) ) {
			return null;
		}
		final String random = new LettersAndDigitsPasswordGenerator().getNewPassword(6, 6);
		final String unid = unidPrefix + lra + random;
		unidfnrSession.storeUnidFnrData(unid, fnr);
		return unid;
	}


    @Override
    public String getReadableName() {
        return "Norwegian FNR to Unid Converter";
    }

	
}
