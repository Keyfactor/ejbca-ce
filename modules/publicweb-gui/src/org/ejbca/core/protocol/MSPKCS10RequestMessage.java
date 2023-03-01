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
package org.ejbca.core.protocol;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;

/** Extends the PKCS10RequestMessgae and contains a few function to parse MS specific information like GUID, DNS, Template etc..
 */
public class MSPKCS10RequestMessage extends PKCS10RequestMessage {
	
	private static final long serialVersionUID = 2936342787428871121L;
    private static final Logger log = Logger.getLogger(MSPKCS10RequestMessage.class);

	public MSPKCS10RequestMessage() {
		super();
	}

	public MSPKCS10RequestMessage(byte[] msg) throws IOException {
		super(msg);
	}
    
	public MSPKCS10RequestMessage(PKCS10CertificationRequest p10) throws IOException {
		super(new JcaPKCS10CertificationRequest(p10));
	}

    public static final String szOID_CERTIFICATE_TEMPLATE_V2 = "1.3.6.1.4.1.311.21.7";		//MicrosoftObjectIdentifiers.microsoftCertTemplateV2?
    public static final String szOID_CMC_REG_INFO = "1.3.6.1.5.5.7.7.18";
    public static final String szOID_REQUEST_CLIENT_INFO = "1.3.6.1.4.1.311.21.20";
    public static final String szOID_ENROLL_CERTTYPE_EXTENSION = "1.3.6.1.4.1.311.20.2";
    public static final String szOID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
    public static final String someTemplateOID = "1.3.6.1.4.1.311.21.8.4014942.3497959.5914804.3829722.12246394.103.3066650.1537810";
    public static final String OID_GUID = "1.3.6.1.4.1.311.25.1";
    
    /**
     * Returns the MS request client info object (1.3.6.1.4.1.311.21.20) as an ArrayList<String>.
     * 
     * E.g. an Machine-template request contains the following structure
     *     SEQUENCE {
     *         	 209    9:         OBJECT IDENTIFIER '1 3 6 1 4 1 311 21 20'
     *             	 220   57:         SET {
     *                 	 222   55:           SEQUENCE {
     *                     	 224    1:             INTEGER 1
     *                         	 227   18:             UTF8String 'host.company.local'
     *                          247   21:             UTF8String 'COMPANY\Administrator'
     *                          270    7:             UTF8String 'certreq'
     *    	         :             }
     *    	         :           }
     *    	         :         }
     */
    private List<String> getMSRequestInfo() {
        ArrayList<String> ret = new ArrayList<String>(); 
        if (pkcs10 == null) {
        	log.error("PKCS10 not inited!");
        	return ret;
        }
        // Get attributes
        Attribute[] attributes = pkcs10.getAttributes(new ASN1ObjectIdentifier(szOID_REQUEST_CLIENT_INFO));
        if (attributes.length == 0) {
                return ret;                
        } else {
            ASN1Set values = attributes[0].getAttrValues();
            if (values.size() == 0) {
            	return ret;
            }
            final ASN1Sequence seq = ASN1Sequence.getInstance(values.getObjectAt(0));
            Enumeration<?> enumeration = seq.getObjects();
            while (enumeration.hasMoreElements()) {
            	Object current = enumeration.nextElement();
            	if (current instanceof DERPrintableString) {
                	ret.add(ASN1PrintableString.getInstance(current).getString());
            	} else if (current instanceof DERUTF8String) {
                	ret.add(ASN1UTF8String.getInstance(current).getString());
            	} else if (current instanceof ASN1Integer) {
                	ret.add(ASN1Integer.getInstance(current).toString());
            	} else {
            		ret.add("Unsupported type: " + current.getClass().getName());
            	}
            }
            Iterator<String> iter = ret.iterator();
            while (iter.hasNext()) {
            	log.info("TEMP-DEBUG-: " + iter.next());
            }
        }
        return ret;
    }
    
    /**
     * Returns the DNS of the MS request client info object (1.3.6.1.4.1.311.21.20) as a String.
     * 
     * This is probably the machine from where the reqeust was made.
     */
    public String getMSRequestInfoDNS() {
    	List<String> ri = getMSRequestInfo();
    	if (ri.size() != 0) {
    		return (String) ri.get(1);
    	} else {
    		return null;
    	}
    }

    /**
     * Returns the name of the Certificate Template or null if not available or not known.
     */
    public String getMSRequestInfoTemplateName() {
    	if (pkcs10 == null) {
    		log.error("PKCS10 not inited!");
    		return null;
    	}
        // Get attributes
        Attribute[] attributes = pkcs10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes.length == 0) {
        	log.error("Cannot find request extension.");
        	return null;
        }
        ASN1Set set = attributes[0].getAttrValues();
        final ASN1Sequence seq = ASN1Sequence.getInstance(set.getObjectAt(0));
        Enumeration<?> enumeration = seq.getObjects();
        while (enumeration.hasMoreElements()) {
        	final ASN1Sequence seq2 = ASN1Sequence.getInstance(enumeration.nextElement());
        	ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(seq2.getObjectAt(0));
        	if (szOID_ENROLL_CERTTYPE_EXTENSION.equals(oid.getId())) {
        		try {
        			final ASN1OctetString dos = ASN1OctetString.getInstance(seq2.getObjectAt(1));
        			ASN1InputStream dosAsn1InputStream = new ASN1InputStream(new ByteArrayInputStream(dos.getOctets()));
                    try {
                        final ASN1String derobj = (ASN1String) dosAsn1InputStream.readObject();
                        return derobj.getString();
                    } finally {
                        dosAsn1InputStream.close();
                    }
        		} catch (IOException e) {
        			log.error(e);
        		}
        	}
        }
        return null;
    }

    /**
     * Returns a String vector with known subject altnames:
     *   [0] Requested GUID
     *   [1] Requested DNS
     */
    public String[] getMSRequestInfoSubjectAltnames() {
    	String[] ret = new String[2];	// GUID, DNS so far..
    	if (pkcs10 == null) {
    		log.error("PKCS10 not inited!");
    		return ret;
    	}
        // Get attributes
        Attribute[] attributes = pkcs10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes.length != 0) {
            final ASN1Set set = attributes[0].getAttrValues();
            final ASN1Sequence seq = ASN1Sequence.getInstance(set.getObjectAt(0));
            final Enumeration<?> enumeration = seq.getObjects();
            while (enumeration.hasMoreElements()) {
            	final ASN1Sequence seq2 = ASN1Sequence.getInstance(enumeration.nextElement());
            	final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(seq2.getObjectAt(0));
            	if ("2.5.29.17".equals(oid.getId())) {	//SubjectAN
            		try {
            			final ASN1OctetString dos = ASN1OctetString.getInstance(seq2.getObjectAt(2));
            			final ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(dos.getOctets()));
            			while (ais.available()>0) {
                			ASN1Sequence seq3 = ASN1Sequence.getInstance(ais.readObject());
                			Enumeration<?> enum1 = seq3.getObjects();
                			while (enum1.hasMoreElements()) {
                				final ASN1TaggedObject dto = ASN1TaggedObject.getInstance(enum1.nextElement());
                				if (dto.getTagNo() == 0) {
                					// Sequence of OIDs and tagged objects
                					final ASN1Sequence ds = ASN1Sequence.getInstance(dto.getObject());
                					final ASN1ObjectIdentifier doid = ASN1ObjectIdentifier.getInstance(ds.getObjectAt(0));
                        			if (OID_GUID.equals((doid).getId())) {
                            			final ASN1OctetString dos3 = ASN1OctetString.getInstance((ASN1TaggedObject.getInstance(ds.getObjectAt(1)).getObject()));
                            			ret[0] = dos3.toString().substring(1); // Removes the initial #-sign
                        			}
                				} else if (dto.getTagNo() == 2) {
                					// DNS
                					final ASN1OctetString dos3 = ASN1OctetString.getInstance(dto.getObject());
                					ret[1] = new String(dos3.getOctets());
                				}
                			}
            			}
            			ais.close();
            		} catch (IOException e) {
						log.error(e);
					}
            	}
            }
        }
    	return ret;
    }

}
