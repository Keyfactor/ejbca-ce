package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;

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
        final BaseCmpMessage pkiRequestBase = mock(BaseCmpMessage.class);
        when(pkiRequestBase.getHeader()).thenReturn(pkiRequestHeader);
        when(pkiRequestBase.getSender()).thenReturn(sender);
        when(pkiRequestBase.getRecipient()).thenReturn(recipient);
        
        // We cannot pass any null objects, so here we go
        final FailInfo errorCode = FailInfo.BAD_TIME;
        final String errorDescription = "Testing not allowed";
        final int requestId = 0;
        final int requestType = 0;
        final CmpPbeVerifyer cmpPbeVerifier = mock(CmpPbeVerifyer.class);
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
        
        // Assert transaction ID set in CMP response
        assertTrue(generalPkiMessage1.getHeader().getTransactionID() != null);
        assertTrue(generalPkiMessage2.getHeader().getTransactionID() != null);
        assertTrue(generalPkiMessage3.getHeader().getTransactionID() != null);
        assertTrue(generalPkiMessage4.getHeader().getTransactionID() != null);
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
        final BaseCmpMessage pkiRequestBase = mock(BaseCmpMessage.class);
        when(pkiRequestBase.getHeader()).thenReturn(pkiRequestHeader);
        when(pkiRequestBase.getSender()).thenReturn(sender);
        when(pkiRequestBase.getRecipient()).thenReturn(recipient);
        // BaseCmpMessage stores fields base64-encoded internally
        when(pkiRequestBase.getSenderNonce()).thenReturn(new String(Base64.encodeBase64(senderNonce)));
        
        // We cannot pass any null objects, so here we go
        final FailInfo errorCode = FailInfo.BAD_TIME;
        final String errorDescription = "Testing not allowed";
        final int requestId = 0;
        final int requestType = 0;
        final CmpPbeVerifyer cmpPbeVerifier = mock(CmpPbeVerifyer.class);
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
        
        // The encoded response is DER encoded when calling createUnprotectedErrorMessage
        final byte[] expected = new DEROctetString(senderNonce).getEncoded();
        assertArrayEquals(expected, generalPkiMessage1.getHeader().getRecipNonce().getEncoded());
        assertArrayEquals(expected, generalPkiMessage2.getHeader().getRecipNonce().getEncoded());
        assertArrayEquals(expected, generalPkiMessage3.getHeader().getRecipNonce().getEncoded());
        assertArrayEquals(expected, generalPkiMessage4.getHeader().getRecipNonce().getEncoded());
    }
}
