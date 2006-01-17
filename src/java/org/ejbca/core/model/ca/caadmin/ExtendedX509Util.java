package org.ejbca.core.model.ca.caadmin;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * 
 * @version $Id: ExtendedX509Util.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 *
 */
class ExtendedX509Util
{
    private static Hashtable algorithms = new Hashtable();
    private static Hashtable algorithmParameters = new Hashtable();
    
    static
    {   
        algorithms.put("MD2WITHRSAENCRYPTION", new DERObjectIdentifier("1.2.840.113549.1.1.2"));
        algorithms.put("MD2WITHRSA", new DERObjectIdentifier("1.2.840.113549.1.1.2"));
        algorithms.put("MD5WITHRSAENCRYPTION", new DERObjectIdentifier("1.2.840.113549.1.1.4"));
        algorithms.put("MD5WITHRSA", new DERObjectIdentifier("1.2.840.113549.1.1.4"));
        algorithms.put("SHA1WITHRSAENCRYPTION", new DERObjectIdentifier("1.2.840.113549.1.1.5"));
        algorithms.put("SHA1WITHRSA", new DERObjectIdentifier("1.2.840.113549.1.1.5"));
        algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("RIPEMD160WITHRSAENCRYPTION", new DERObjectIdentifier("1.3.36.3.3.1.2"));
        algorithms.put("RIPEMD160WITHRSA", new DERObjectIdentifier("1.3.36.3.3.1.2"));
        algorithms.put("SHA1WITHDSA", new DERObjectIdentifier("1.2.840.10040.4.3"));
        algorithms.put("DSAWITHSHA1", new DERObjectIdentifier("1.2.840.10040.4.3"));
        algorithms.put("SHA1WITHECDSA", new DERObjectIdentifier("1.2.840.10045.4.1"));
        algorithms.put("ECDSAWITHSHA1", new DERObjectIdentifier("1.2.840.10045.4.1"));
        algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("SHA256WITHRSAANDMGF1", new DERObjectIdentifier("1.2.840.113549.1.1.10"));        
        
        algorithmParameters.put("MD2WITHRSAENCRYPTION", new DERNull());
        algorithmParameters.put("MD2WITHRSA", new DERNull());
        algorithmParameters.put("MD5WITHRSAENCRYPTION", new DERNull());
        algorithmParameters.put("MD5WITHRSA", new DERNull());
        algorithmParameters.put("SHA1WITHRSAENCRYPTION", new DERNull());
        algorithmParameters.put("SHA1WITHRSA", new DERNull());
        algorithmParameters.put("SHA224WITHRSAENCRYPTION", new DERNull());
        algorithmParameters.put("SHA224WITHRSA", new DERNull());
        algorithmParameters.put("SHA256WITHRSAENCRYPTION", new DERNull());
        algorithmParameters.put("SHA256WITHRSA", new DERNull());
        algorithmParameters.put("SHA384WITHRSAENCRYPTION", new DERNull());
        algorithmParameters.put("SHA384WITHRSA", new DERNull());
        algorithmParameters.put("SHA512WITHRSAENCRYPTION", new DERNull());
        algorithmParameters.put("SHA512WITHRSA", new DERNull());
        algorithmParameters.put("RIPEMD160WITHRSAENCRYPTION", new DERNull());
        algorithmParameters.put("RIPEMD160WITHRSA", new DERNull());
        algorithmParameters.put("SHA1WITHDSA", new DERNull());
        algorithmParameters.put("DSAWITHSHA1", new DERNull());
        algorithmParameters.put("SHA1WITHECDSA", new DERNull());
        algorithmParameters.put("ECDSAWITHSHA1", new DERNull());
        algorithmParameters.put("GOST3411WITHGOST3410", new DERNull());
        algorithmParameters.put("SHA256WITHRSAANDMGF1", new RSASSAPSSparams( new AlgorithmIdentifier(new DERObjectIdentifier("2.16.840.1.101.3.4.2.1"), new DERNull()), 
                                                                             new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(new DERObjectIdentifier("2.16.840.1.101.3.4.2.1"), new DERNull())),  
                                                                             new DERInteger(32), new DERInteger(1)
                                                                             ).getDERObject());
        
        
    }
    
    static DERObjectIdentifier getAlgorithmOID(
        String algorithmName)
    {
        algorithmName = algorithmName.toUpperCase();
        
        if (algorithms.containsKey(algorithmName))
        {
            return (DERObjectIdentifier)algorithms.get(algorithmName);
        }
        
        return new DERObjectIdentifier(algorithmName);
    }
    
    static DERObject getAlgorithmParameters(
            String algorithmName)
        {
            algorithmName = algorithmName.toUpperCase();
            
            if (algorithmParameters.containsKey(algorithmName))
            {
                return (DERObject)algorithmParameters.get(algorithmName);
            }
            
            return new DERNull();
        }
    
    static Iterator getAlgNames()
    {
        Enumeration e = algorithms.keys();
        ArrayList   l = new ArrayList();
        
        while (e.hasMoreElements())
        {
            l.add(e.nextElement());
        }
        
        return l.iterator();
    }
}
