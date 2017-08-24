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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;

import static org.easymock.EasyMock.*;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.junit.Test;

/**
 * JUnit tests for CmpMessageHelper.
 * 
 * @version $Id$
 */
public class CmpMessageHelperTest {

    /**
     * Asserts that the transactionID is present in the CMP response when the helper answers 
     * with an error even when the transaction ID was not set by the client. See RFC 4210 page 25.
     */
    @Test
    public void testTransactionIdSetOnError() throws IOException, CertificateEncodingException {
        final GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
        final GeneralName recipient = new GeneralName(new X500Name("CN=Recipient"));
        final PKIHeader pkiRequestHeader = new PKIHeader(PKIHeader.CMP_2000, sender, recipient);
        // Body could be anything, but we use an error here
        final ErrorMsgContent errorMsgContent = new ErrorMsgContent(
                new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText("Testing")));
        final PKIBody pkiResponseBody = new PKIBody(PKIBody.TYPE_ERROR, errorMsgContent);
        
        final PKIMessage pkiRequestMessage = new PKIMessage(pkiRequestHeader, pkiResponseBody);
        final BaseCmpMessage pkiRequestBase = createNiceMock(BaseCmpMessage.class);
        expect(pkiRequestBase.getHeader()).andReturn(pkiRequestHeader);
        expect(pkiRequestBase.getSender()).andReturn(sender);
        expect(pkiRequestBase.getRecipient()).andReturn(recipient);
        replay(pkiRequestBase);
        
        // We cannot pass any null objects, so here we go
        final FailInfo errorCode = FailInfo.BAD_TIME;
        final String errorDescription = "Testing not allowed";
        final int requestId = 0;
        final int requestType = 0;
        final CmpPbeVerifyer cmpPbeVerifier = createNiceMock(CmpPbeVerifyer.class);
        replay(cmpPbeVerifier);
        final String keyId = "0";
        final String responseProtocol = "cmp";
        
        final ResponseMessage responseMessage1 = CmpMessageHelper.createUnprotectedErrorMessage(pkiRequestMessage.getEncoded(), errorCode, errorDescription);
        final ResponseMessage responseMessage2 = CmpMessageHelper.createUnprotectedErrorMessage(pkiRequestBase, errorCode, errorDescription);
        final ResponseMessage responseMessage3 = CmpMessageHelper.createUnprotectedErrorMessage(pkiRequestHeader, errorCode, errorDescription);
        final ResponseMessage responseMessage4 = CmpMessageHelper.createErrorMessage(
                pkiRequestBase, 
                errorCode,
                errorDescription, 
                requestId, 
                requestType, cmpPbeVerifier, 
                keyId, 
                responseProtocol);
        final byte[] responseMessage5 = CmpMessageHelper.createUnprotectedErrorMessage(errorDescription);
        
        final GeneralPKIMessage generalPkiMessage1 = new GeneralPKIMessage(responseMessage1.getResponseMessage());
        final GeneralPKIMessage generalPkiMessage2 = new GeneralPKIMessage(responseMessage2.getResponseMessage());
        final GeneralPKIMessage generalPkiMessage3 = new GeneralPKIMessage(responseMessage3.getResponseMessage());
        final GeneralPKIMessage generalPkiMessage4 = new GeneralPKIMessage(responseMessage4.getResponseMessage());
        final GeneralPKIMessage generalPkiMessage5 = new GeneralPKIMessage(responseMessage5);
        
        // Assert transaction ID set in CMP response
        assertTrue(generalPkiMessage1.getHeader().getTransactionID() != null);
        assertTrue(generalPkiMessage2.getHeader().getTransactionID() != null);
        assertTrue(generalPkiMessage3.getHeader().getTransactionID() != null);
        assertTrue(generalPkiMessage4.getHeader().getTransactionID() != null);
        assertTrue(generalPkiMessage5.getHeader().getTransactionID() != null);
    }
    
    /**
     * Asserts recipNonce has been properly copied from the senderNonce field when the helper answers with
     * an error.
     */
    @Test
    public void testRecipNonceCopiedCorrectly() throws IOException, CertificateEncodingException {
        final GeneralName sender = new GeneralName(new X500Name("CN=Sender"));
        final GeneralName recipient = new GeneralName(new X500Name("CN=Recipient"));
        final byte[] senderNonce = "1337".getBytes();
        final PKIHeader pkiRequestHeader = new PKIHeaderBuilder(PKIHeader.CMP_2000, sender, recipient).
                setSenderNonce(senderNonce).
                build();
        // Body could be anything, but we use an error here
        final ErrorMsgContent errorMsgContent = new ErrorMsgContent(
                new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText("Testing")));
        final PKIBody pkiResponseBody = new PKIBody(PKIBody.TYPE_ERROR, errorMsgContent);
        
        final PKIMessage pkiRequestMessage = new PKIMessage(pkiRequestHeader, pkiResponseBody);
        final BaseCmpMessage pkiRequestBase = createNiceMock(BaseCmpMessage.class);
        expect(pkiRequestBase.getHeader()).andReturn(pkiRequestHeader);
        expect(pkiRequestBase.getSender()).andReturn(sender);
        expect(pkiRequestBase.getRecipient()).andReturn(recipient);
        // BaseCmpMessage stores fields base64-encoded internally
        expect(pkiRequestBase.getSenderNonce()).andReturn(new String(Base64.encodeBase64(senderNonce)));
        replay(pkiRequestBase);
        
        // We cannot pass any null objects, so here we go
        final FailInfo errorCode = FailInfo.BAD_TIME;
        final String errorDescription = "Testing not allowed";
        final int requestId = 0;
        final int requestType = 0;
        final CmpPbeVerifyer cmpPbeVerifier = createNiceMock(CmpPbeVerifyer.class);
        replay(cmpPbeVerifier);
        final String keyId = "0";
        final String responseProtocol = "cmp";
        
        final ResponseMessage responseMessage1 = CmpMessageHelper.createUnprotectedErrorMessage(pkiRequestMessage.getEncoded(), errorCode, errorDescription);
        final ResponseMessage responseMessage2 = CmpMessageHelper.createUnprotectedErrorMessage(pkiRequestBase, errorCode, errorDescription);
        final ResponseMessage responseMessage3 = CmpMessageHelper.createUnprotectedErrorMessage(pkiRequestHeader, errorCode, errorDescription);
        final ResponseMessage responseMessage4 = CmpMessageHelper.createErrorMessage(
                pkiRequestBase, 
                errorCode,
                errorDescription, 
                requestId, 
                requestType, cmpPbeVerifier, 
                keyId, 
                responseProtocol);
        
        final GeneralPKIMessage generalPkiMessage1 = new GeneralPKIMessage(responseMessage1.getResponseMessage());
        final GeneralPKIMessage generalPkiMessage2 = new GeneralPKIMessage(responseMessage2.getResponseMessage());
        final GeneralPKIMessage generalPkiMessage3 = new GeneralPKIMessage(responseMessage3.getResponseMessage());
        final GeneralPKIMessage generalPkiMessage4 = new GeneralPKIMessage(responseMessage4.getResponseMessage());
        
        // The encoded response is DER encoded
        final byte[] expected = new DEROctetString(senderNonce).getEncoded();
        
        assertArrayEquals(expected, generalPkiMessage1.getHeader().getRecipNonce().getEncoded());
        assertArrayEquals(expected, generalPkiMessage2.getHeader().getRecipNonce().getEncoded());
        assertArrayEquals(expected, generalPkiMessage3.getHeader().getRecipNonce().getEncoded());
        assertArrayEquals(expected, generalPkiMessage4.getHeader().getRecipNonce().getEncoded());
    }
}
