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
 
package org.ejbca.ui.web.pub.inspect;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.util.CertTools;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.CvcException;

/**
 * This bean dumps contents of certificate and certificate request as text. CVC dump or ASN.1 dump.
 * 
 * To make it easy to use from JSTL pages, most methods take no arguments.
 * The arguments are supplied as member variables instead. <br>
 * 
 * @version $Id$
 */
public class CertAndRequestDumpBean {
	
	private byte[] bytes;
	private String type = "unknown";

	/**
	 * Empty default constructor.
	 */
	public CertAndRequestDumpBean() {
	}

	public void setBytes(final byte[] b) {
		if (b.length < 10000) {
			// don't accept anything too large
			this.bytes = b;
			// Figure out type of request
			getDump(); // as side effect sets type variable
		} else {
			type = "too large";
		}
	}
	
	/** Dumps contents, and updates "type" variable as side-effect.
	 * 
	 * @return String containing raw text output or null of input is null, or error message if input invalid.
	 */
	public String getDump() {
		String ret = null;
		if (bytes == null) {
			return null;
		}
		final byte[] requestBytes = RequestMessageUtils.getDecodedBytes(bytes);
		ret = getCvcDump(false);
		if ((ret == null) && (requestBytes != null) && (requestBytes.length > 0)) {
			// Not a CVC request, perhaps a PKCS10 request
			try {
				final PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(requestBytes);
//				ret = pkcs10.toString();
				final ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(pkcs10.getEncoded()));
				final ASN1Primitive obj = ais.readObject();
				ais.close();
				ret = ASN1Dump.dumpAsString(obj);
				type = "PKCS#10";
			} catch (IOException e1) {
				 // ignore, move on to certificate decoding
			} catch (IllegalArgumentException e1) {
				// ignore, move on to certificate decoding
			} catch (ClassCastException e2) {
				// ignore, move on to certificate decoding
			}
		} else if (ret != null) {
			type = "CVC";
		}
		if (ret == null) {
			// Not a CVC object or PKCS10 request message, perhaps a X.509 certificate?
			try {
				final Certificate cert = getCert(bytes);
				ret = CertTools.dumpCertificateAsString(cert);
				type = "X.509";
			} catch (Exception e) {
				// Not a X.509 certificate either...try to simply decode asn.1
				try {
					final ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(bytes));
					final ASN1Primitive obj = ais.readObject();
					ais.close();
					if (obj != null) {
						ret = ASN1Dump.dumpAsString(obj);
						type = "ASN.1";						
					}
				} catch (IOException e1) {
					// Last stop, say what the error is
					ret = e1.getMessage();
				}
			}						
		}
		return ret;
	}

	public String getType() {
		return type;
	}

	public String getCvcDump(final boolean returnMessageOnError) {
		String ret = null;
		final byte[] requestBytes = RequestMessageUtils.getDecodedBytes(bytes);
		try {
			final CVCObject obj = getCVCObject(requestBytes);
			ret = obj.getAsText("");
		} catch (Exception e) {
			// Not a CVC request, perhaps a PKCS10 request
			if (returnMessageOnError) {
				ret = e.getMessage();				
			}
		}
		return ret;
	}

	private static CVCObject getCVCObject(final byte[] cvcdata) throws IOException, CvcException, CertificateException {
		CVCObject ret = null;
		try {
			ret = CertificateParser.parseCVCObject(cvcdata);
		} catch (Exception e) {
			try {
				// this was not parseable, try to see it it was a PEM certificate
				final Collection<Certificate> col = CertTools.getCertsFromPEM(new ByteArrayInputStream(cvcdata), Certificate.class);
				final Certificate cert = col.iterator().next();
	        	ret = CertificateParser.parseCVCObject(cert.getEncoded());
			} catch (Exception ie) {
				// this was not a PEM cert, try to see it it was a PEM certificate req
				final byte[] req = RequestMessageUtils.getRequestBytes(cvcdata);
				ret = CertificateParser.parseCVCObject(req);
			}
		}
		return ret;
	}

	private Certificate getCert(final byte[] certbytes) throws CertificateException {
		  Certificate cert = null;
		  Collection<Certificate> cachain = null;
		  try {
			  final Collection<Certificate> certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes), Certificate.class);
			  final Iterator<Certificate> iter = certs.iterator();
			  cert = iter.next();	
			  if (iter.hasNext()) {
				  // There is a complete certificate chain returned here
				  cachain = new ArrayList<Certificate>();
				  while (iter.hasNext()) {
					  final Certificate chaincert = iter.next();
					  cachain.add(chaincert);
				  }
			  }
		  } catch (CertificateException e) {
			  // See if it is a single binary certificate
			  cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
		  }
		  return cert;
	}

}
