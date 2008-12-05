package org.ejbca.core.model.ca.certextensions.standard;

import java.security.PublicKey;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERPrintableString;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;

public class SeisCardNumber extends StandardCertificateExtension {

	private static final Logger log = Logger.getLogger(SeisCardNumber.class);

    /** OID for creating Smartcard Number Certificate Extension
     *  SEIS Cardnumber Extension according to SS 614330/31 */
    public static final String OID_CARDNUMBER= "1.2.752.34.2.1";

	/**
	 * Constructor for creating the certificate extension 
	 */
	public SeisCardNumber() {
		super();
	}
	
	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(CertificateProfile certProf) {
		super.setOID(SeisCardNumber.OID_CARDNUMBER);
		super.setCriticalFlag(false);
	}
	

	public DEREncodable getValue(UserDataVO userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey)
			throws CertificateExtentionConfigurationException, CertificateExtensionException {
		String cardnumber = userData.getCardNumber();
		DEREncodable ret = null;
		if (StringUtils.isNotEmpty(cardnumber)) {
			ret = new DERPrintableString(cardnumber);
			if (log.isDebugEnabled()) {
				log.debug("Seis card numer: "+cardnumber);
			}
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Seis card numer is empty");
			}			
		}
		return ret;
	}

}
