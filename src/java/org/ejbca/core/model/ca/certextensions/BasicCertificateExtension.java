/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.ca.certextensions;

import java.math.BigInteger;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * The default basic certificate extension that has two property.
 * 
 * 'value'    : The value returned
 * 'encoding' : How the value is encoded.
 * 
 * See dokumentation for more information.
 * 
 * @author Philip Vendil 2007 jan 5
 *
 * @version $Id: BasicCertificateExtension.java,v 1.4 2007-09-05 08:24:33 jeklund Exp $
 */

public class BasicCertificateExtension extends CertificateExtension {

	private static final InternalResources intres = InternalResources.getInstance();
	
	private static String ENCODING_DERBITSTRING       = "DERBITSTRING";	 
	private static String ENCODING_DERINTEGER         = "DERINTEGER";
	private static String ENCODING_DEROCTETSTRING	  = "DEROCTETSTRING";
	private static String ENCODING_DERBOOLEAN         = "DERBOOLEAN";	      
	private static String ENCODING_DERPRINTABLESTRING = "DERPRINTABLESTRING";	 
	private static String ENCODING_DERUTF8STRING      = "DERUTF8STRING";	 
	private static String ENCODING_DERIA5STRING       = "DERIA5STRING";	 
	private static String ENCODING_DERNULL            = "DERNULL";
	
	// Defined Properties
	private static String PROPERTY_VALUE    = "value";
	private static String PROPERTY_ENCODING = "encoding";
	
	private DEREncodable dEREncodable = null;
	
	/**
	 * Returns the defined property 'value' in the encoding 
	 * specified in 'encoding'.
	 * 
	 * @param userData not used
	 * @param ca not used
	 * @param certProfile not used
	 * @see org.ejbca.core.model.ca.certextensions.CertificateExtension#getValue(org.ejbca.core.model.ra.UserDataVO, org.ejbca.core.model.ca.caadmin.CA, org.ejbca.core.model.ca.certificateprofiles.CertificateProfile)
	 */
	public DEREncodable getValue(UserDataVO userData, CA ca,
			CertificateProfile certProfile)
			throws CertificateExtentionConfigurationException {

		if(dEREncodable == null){
		  String value = getProperties().getProperty(PROPERTY_VALUE);		  
		  String encoding = getProperties().getProperty(PROPERTY_ENCODING);		  
		  
		  if(!encoding.equalsIgnoreCase(ENCODING_DERNULL) && (value == null || value.trim().equals(""))){
			  throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.incorrectvalue", new Integer(getId())));
		  }
		  
		  if(encoding.equalsIgnoreCase(ENCODING_DERBITSTRING)){
			  dEREncodable = parseDERBitString(value);
		  }else
			  if(encoding.equalsIgnoreCase(ENCODING_DERINTEGER)){
				  dEREncodable = parseDERInteger(value);
			  }else
				  if(encoding.equalsIgnoreCase(ENCODING_DEROCTETSTRING)){
					  dEREncodable = parseDEROctetString(value);
				  }else
					  if(encoding.equalsIgnoreCase(ENCODING_DERBOOLEAN)){
						  dEREncodable = parseDERBoolean(value);
					  }else 
						  if(encoding.equalsIgnoreCase(ENCODING_DERPRINTABLESTRING)){
							  dEREncodable = parseDERPrintableString(value);
						  }else
							  if(encoding.equalsIgnoreCase(ENCODING_DERUTF8STRING)){
								  dEREncodable = parseDERUTF8String(value);
							  }else
								  if(encoding.equalsIgnoreCase(ENCODING_DERIA5STRING)){
									  dEREncodable = parseDERIA5String(value);
								  }else
									  if(encoding.equalsIgnoreCase(ENCODING_DERNULL)){
										  dEREncodable = new DERNull();
									  }else{
										  throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.incorrectenc",new Integer(getId())));
									  }
		}
		
		return dEREncodable;
	}

	private DEREncodable parseDERBitString(String value) throws CertificateExtentionConfigurationException {
		DEREncodable retval = null;
		try{
			BigInteger bigInteger = new BigInteger(value,2);			
			int padBits = value.length() - 1 - value.lastIndexOf("1");
			if(padBits == 8){
				padBits = 0;
			}
			byte[] byteArray = bigInteger.toByteArray();
			if (byteArray[0] == 0) { 
				// Remove empty extra byte
				byte[] shorterByteArray = new byte[byteArray.length-1];
				for (int i=0; i<shorterByteArray.length; i++) {
					shorterByteArray[i] = byteArray[i+1];
				}
				byteArray = shorterByteArray; 
			}
			retval = new DERBitString(byteArray, padBits);
		}catch(NumberFormatException e){
			throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue",value,new Integer(getId())));
		}
		
		return retval;
	}
	
	private DEREncodable parseDERInteger(String value) throws CertificateExtentionConfigurationException {
		DEREncodable retval = null; 
		try{
			BigInteger intValue = new BigInteger(value,10);
			retval = new DERInteger(intValue);
		}catch(NumberFormatException e){
			throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue",value,new Integer(getId())));
		}

		return retval;
	}
	
	private DEREncodable parseDEROctetString(String value) throws CertificateExtentionConfigurationException {
		DEREncodable retval = null;
		if(value.matches("^\\p{XDigit}*")){		  
		  byte[] bytes = Hex.decode(value);
		  retval = new DEROctetString(bytes);
		}else{		
			throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue",value,new Integer(getId())));
		}
		return retval;
	}
	
	private DEREncodable parseDERBoolean(String value) throws CertificateExtentionConfigurationException {
		DEREncodable retval = null;
		if(value.equalsIgnoreCase("TRUE")){
			retval = DERBoolean.TRUE;
		}
		
		if(value.equalsIgnoreCase("FALSE")){
			retval = DERBoolean.FALSE;
		}
		
		if(retval == null){
			throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue",value,new Integer(getId())));
		}

		return retval;
	}
	
	private DEREncodable parseDERPrintableString(String value) throws CertificateExtentionConfigurationException {
		try{
		  return new DERPrintableString(value,true);
		}catch(java.lang.IllegalArgumentException e){
			throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.basic.illegalvalue",value,new Integer(getId())));
		}
	}
	
	private DEREncodable parseDERUTF8String(String value) {		
		return new DERUTF8String(value);
	}
	private DEREncodable parseDERIA5String(String value) {		
		return new DERIA5String(value, true);
	}


}
