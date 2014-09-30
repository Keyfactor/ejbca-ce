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
package org.ejbca.core.protocol.cmp;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.util.Base64;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Message class for CMP PKI confirm and CertCOnf messages
 * @author tomas
 * @version $Id$
 */
public class GeneralCmpMessage extends BaseCmpMessage {

	private static final Logger log = Logger.getLogger(GeneralCmpMessage .class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
	
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

	public GeneralCmpMessage(final PKIMessage msg) {
		final PKIBody body = msg.getBody();
		final int tag = body.getType();
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
			final CertConfirmContent obj = (CertConfirmContent) body.getContent();
			CertStatus cs;
			try {
			    cs = CertStatus.getInstance(obj.toASN1Primitive());
			} catch(Exception e) {
			    cs = CertStatus.getInstance(((DERSequence) obj.toASN1Primitive()).getObjectAt(0));
			}
			final PKIStatusInfo status = cs.getStatusInfo();
			if (status != null) {
				final int st = status.getStatus().intValue();
				if (st != 0) {
					final String errMsg = intres.getLocalizedMessage("cmp.errorcertconfirmstatus", Integer.valueOf(st));
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
			final RevReqContent rr = (RevReqContent) body.getContent();
			RevDetails rd;
			try {
			    rd = rr.toRevDetailsArray()[0];
			} catch(Exception e) {
			    log.debug("Could not parse the revocation request. Trying to parse it as novosec generated message.");
			    rd = CmpMessageHelper.getNovosecRevDetails(rr);
			    log.debug("Succeeded in parsing the novosec generated request.");
			}
			final CertTemplate ct = rd.getCertDetails();
			final DERInteger serno = ct.getSerialNumber();
			final X500Name issuer = ct.getIssuer();
			if ( (serno != null) && (issuer != null) ) {
				final String errMsg = intres.getLocalizedMessage("cmp.receivedrevreq", issuer.toString(), serno.getValue().toString(16));
				log.info(errMsg);
			} else {
				final String errMsg = intres.getLocalizedMessage("cmp.receivedrevreqnoissuer");
				log.info(errMsg);
			}
		}
		setMessage(msg);
		final PKIHeader header = msg.getHeader();
		if (header.getTransactionID() != null) {
		    final byte[] val = header.getTransactionID().getOctets();
			if (val != null) {
				setTransactionId(new String(Base64.encode(val)));							
			}
		}
		if (header.getSenderNonce() != null) {
		    final byte[] val = header.getSenderNonce().getOctets();
			if (val != null) {
				setSenderNonce(new String(Base64.encode(val)));							
			}
		}
		setRecipient(header.getRecipient());
		setSender(header.getSender());
	}
	
}
