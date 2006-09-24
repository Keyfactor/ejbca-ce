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
package org.ejbca.core.protocol.cmp;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.ejbca.util.Base64;

import com.novosec.pkix.asn1.cmp.CertConfirmContent;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;

/**
 * Message class for CMP PKI confirm and CertCOnf messages
 * @author tomas
 * @version $Id: ConfirmationMessage.java,v 1.3 2006-09-24 13:20:06 anatom Exp $
 */
public class ConfirmationMessage extends BaseCmpMessage {

	private static final Logger log = Logger.getLogger(ConfirmationMessage .class);
	
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    static final long serialVersionUID = 1000L;

	public ConfirmationMessage(PKIMessage msg) {
		PKIBody body = msg.getBody();
		int tag = body.getTagNo();
		if (tag == 19) {
			// this is a PKIConfirmContent
			log.debug("Received a PKIConfirm message");
			// This is a null message, so there is nothing to get here
			//DERNull obj = body.getConf();
		}
		if (tag == 24) {
			// this is a CertConfirmContent
			log.debug("Received a Cert Confirm message");
			CertConfirmContent obj = body.getCertConf();
			PKIStatusInfo status = obj.getPKIStatus();
			if (status != null) {
				int st = status.getStatus().getValue().intValue();
				if (st != 0) {
					log.error("Received a Cert Confirm with status "+st);
					// TODO: if it is rejected, we should revoke the cert?
				}
			}
		}
		setMessage(msg);
		PKIHeader header = msg.getHeader();
		DEROctetString os = header.getTransactionID();
		if (os != null) {
			byte[] val = os.getOctets();
			if (val != null) {
				setTransactionId(new String(Base64.encode(val)));							
			}
		}
		os = header.getSenderNonce();
		if (os != null) {
			byte[] val = os.getOctets();
			if (val != null) {
				setSenderNonce(new String(Base64.encode(val)));							
			}
		}
		setRecipient(header.getRecipient());
		setSender(header.getSender());
	}
	
}
