package se.anatom.ejbca.protocol;

import java.io.*;
import java.util.Vector;
import java.util.Iterator;

import org.apache.log4j.*;

import org.bouncycastle.jce.PKCS7SignedData;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.*;

/** Helper class to handle SCEP PKIOperation messages.
*
* @version  $Id: ScepPkiOpHelper.java,v 1.3 2002-09-21 17:11:12 anatom Exp $
*/
public class ScepPkiOpHelper {

    static private Category cat = Category.getInstance( ScepPkiOpHelper.class.getName() );
    
    public static String id_Verisign = "2.16.840.1.113733";
    public static String id_pki = id_Verisign + 1;
    public static String id_attributes = id_pki + 9;
    public static String id_messageType = id_attributes + 2;
    public static String id_pkiStatus = id_attributes + 3;
    public static String id_failInfo = id_attributes + 4;
    public static String id_senderNonce = id_attributes + 5;
    public static String id_recipientNonce = id_attributes + 6;
    public static String id_transId = id_attributes + 7;
    public static String id_extensionReq = id_attributes + 8;
    
    private SignerInfo si = null;
    /* The messageType attribute specify the type of operation performed by the
     * transaction. This attribute is required in all PKI messages. Currently, the following message types are defined:
     * PKCSReq (19)  -- Permits use of PKCS#10 certificate request
     * CertRep (3)   -- Response to certificate or CRL request
     * GetCertInitial (20)  -- Certificate polling in manual enrollment
     * GetCert (21)  -- Retrieve a certificate
     * GetCRL  (22)  -- Retrieve a CRL
     */
    private String messageType = null;
        
	public ScepPkiOpHelper(byte[] msg) throws IOException {
        cat.debug(">ScepPkiOpHelper");
		// Parse and verify the entegrity of the PKIOperation message PKCS#7
		// TODO: 
        /*
        try {
            PKCS7SignedData pkcs7 = new PKCS7SignedData(msg);
        } catch (Exception e) {
        } */
        /* If this would have been done using the newer CMS it would have made me so much happier... */
		DERConstructedSequence seq =(DERConstructedSequence)(new DERInputStream(new ByteArrayInputStream(msg)).readObject());
		ContentInfo ci = new ContentInfo(seq);
		ContentType ct = ci.getContentType();
		String ctoid = ct.getContentType();
		if (ctoid.equals(CMSObjectIdentifiers.id_signedData.getId())) {
			// This is SignedData so it is a pkcsCertReqSigned, 
			//  pkcsGetCertInitialSigned, pkcsGetCertSigned, pkcsGetCRLSigned
			// (could also be pkcsRepSigned or certOnly, but we don't receive them on the server side

			// Try to find out what kind of message this is
			SignedData sd = (SignedData) ci.getContent();
			Vector sis = sd.getSignerInfos().getInfos();
			if (sis.size() > 0) {
				si =(SignerInfo)sis.get(0); 
                Vector attr = si.getSignedAttrs().getAttributes();
                Iterator iter = attr.iterator();
                while (iter.hasNext()) {
                    Attribute a = (Attribute)iter.next();
                    cat.debug("Found attribute: "+a.getAttrType());
                    if (a.getAttrType().equals(id_messageType))
                        messageType = (String)a.getAttrValues().get(0);
                        cat.debug("Messagetype = "+messageType);
                }
            }
       cat.debug("<ScepPkiOpHelper");
		}

	}
}    