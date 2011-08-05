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
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.util.Base64;
import org.ejbca.core.model.InternalResources;

import com.novosec.pkix.asn1.cmp.CertConfirmContent;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;
import com.novosec.pkix.asn1.cmp.RevDetails;
import com.novosec.pkix.asn1.cmp.RevReqContent;
import com.novosec.pkix.asn1.crmf.CertTemplate;

/**
 * Message class for CMP PKI confirm and CertCOnf messages
 * @author tomas
 * @version $Id$
 */
public class GeneralCmpMessage extends BaseCmpMessage {

	private static final Logger log = Logger.getLogger(GeneralCmpMessage .class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
	
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

	public GeneralCmpMessage(PKIMessage msg) {
		PKIBody body = msg.getBody();
		int tag = body.getTagNo();
		if (tag == 19) {
			// this is a PKIConfirmContent
			if (log.isDebugEnabled()) {
				log.debug("Received a PKIConfirm message");
			}
			// This is a null message, so there is nothing to get here
			//DERNull obj = body.getConf();
		}
		if (tag == 24) {
			// this is a CertConfirmContent
			if (log.isDebugEnabled()) {
				log.debug("Received a Cert Confirm message");
			}
			CertConfirmContent obj = body.getCertConf();
			PKIStatusInfo status = obj.getPKIStatus();
			if (status != null) {
				int st = status.getStatus().getValue().intValue();
				if (st != 0) {
					String errMsg = intres.getLocalizedMessage("cmp.errorcertconfirmstatus", Integer.valueOf(st));
					log.error(errMsg);
					// TODO: if it is rejected, we should revoke the cert?
				}
			}
		}
		if (tag == 11) {
			// this is a RevReqContent,
			if (log.isDebugEnabled()) {
				log.debug("Received a RevReqContent");
			}
			RevReqContent rr = body.getRr();
			RevDetails rd = rr.getRevDetails(0);
			CertTemplate ct = rd.getCertDetails();
			DERInteger serno = ct.getSerialNumber();
			X509Name issuer = ct.getIssuer();
			if ( (serno != null) && (issuer != null) ) {
				String errMsg = intres.getLocalizedMessage("cmp.receivedrevreq", issuer.toString(), serno.getValue().toString(16));
				log.info(errMsg);
			} else {
				String errMsg = intres.getLocalizedMessage("cmp.receivedrevreqnoissuer");
				log.info(errMsg);
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
