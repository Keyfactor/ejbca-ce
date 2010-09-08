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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Vector;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.keystore.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

/**
 * Test to verify that CrmfRequestMessage can be properly Serialized.
 * Previously the fields in the inherited class BaseCmpMessage could not be properly Serialized.
 * 
 * @version $Id$
 */
public class CrmfRequestMessageTest extends TestCase {

	/**
     * @param name name
     */
    public CrmfRequestMessageTest(String name) {
        super(name);
    	CryptoProviderTools.installBCProvider();
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    public void testCrmfRequestMessageSerialization() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    	// Create a bogus PKIMessage
		KeyPair keys = KeyTools.genKeys("1024", "RSA");
		OptionalValidity myOptionalValidity = new OptionalValidity();
		org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
		org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
		myOptionalValidity.setNotBefore(nb);
		myOptionalValidity.setNotAfter(na);
		CertTemplate myCertTemplate = new CertTemplate();
		myCertTemplate.setValidity( myOptionalValidity );
		myCertTemplate.setIssuer(new X509Name("CN=bogusIssuer"));
		myCertTemplate.setSubject(new X509Name("CN=bogusSubject"));
		byte[]                  bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream         dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
		myCertTemplate.setPublicKey(keyInfo);
		ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
		DEROutputStream         dOut = new DEROutputStream(bOut);
		Vector<X509Extension> values = new Vector<X509Extension>();
		Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
		int bcku = X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment | X509KeyUsage.nonRepudiation;
		X509KeyUsage ku = new X509KeyUsage(bcku);
		bOut = new ByteArrayOutputStream();
		dOut = new DEROutputStream(bOut);
		dOut.writeObject(ku);
		byte[] value = bOut.toByteArray();
		X509Extension kuext = new X509Extension(false, new DEROctetString(value));
		values.add(kuext);
		oids.add(X509Extensions.KeyUsage);
        myCertTemplate.setExtensions(new X509Extensions(oids, values));
        CertRequest myCertRequest = new CertRequest(new DERInteger(4), myCertTemplate);
        CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest);
        ProofOfPossession myProofOfPossession = new ProofOfPossession(new DERNull(), 0);
        myCertReqMsg.setPop(myProofOfPossession);
        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.regCtrl_regToken, new DERUTF8String("foo123"));
        myCertReqMsg.addRegInfo(av);
        CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);
        PKIHeader myPKIHeader = new PKIHeader(new DERInteger(2), new GeneralName(new X509Name("CN=bogusSubject")), new GeneralName(new X509Name("CN=bogusIssuer")));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        myPKIHeader.setSenderNonce(new DEROctetString(CmpMessageHelper.createSenderNonce()));
        myPKIHeader.setTransactionID(new DEROctetString(CmpMessageHelper.createSenderNonce()));
        PKIBody myPKIBody = new PKIBody(myCertReqMessages, 0);
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);
    	// Create a bogus CrmfRequestMessage
    	CrmfRequestMessage crmf = new CrmfRequestMessage(myPKIMessage, "SomeCA", true, null);
    	crmf.setPbeParameters("keyId", "key", "digestAlg", "macAlg", 100);
    	// Serialize it
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream oos = new ObjectOutputStream(baos);
    	oos.writeObject(crmf);
    	// Deserialize it
    	ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
    	Object o = ois.readObject();
    	assertTrue("The deserialized object was not of type CrmfRequestMessage.", o instanceof CrmfRequestMessage);
    	CrmfRequestMessage crmf2 = (CrmfRequestMessage) o;
    	assertEquals("Inherited object was not properly deserilized: ", "macAlg", crmf2.getPbeMacAlg());
    }

}
