package org.ejbca.core.model.ca.caadmin;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.util.encoders.Hex;

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

/** Class copied from BouncyCastle and extended to supoprt RSA-DSS signatures
 * 
 * @version $Id: ExtendedX509CertificateObject.java,v 1.2 2006-02-08 07:31:48 anatom Exp $
 *
 */ 
public class ExtendedX509CertificateObject
    extends X509Certificate
    implements PKCS12BagAttributeCarrier
{
    private X509CertificateStructure    c;
    private Hashtable                   pkcs12Attributes = new Hashtable();
    private Vector                      pkcs12Ordering = new Vector();

    public ExtendedX509CertificateObject(
        X509CertificateStructure    c)
    {
        this.c = c;
    }

    public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        this.checkValidity(new Date());
    }

    public void checkValidity(
        Date    date)
        throws CertificateExpiredException, CertificateNotYetValidException
    {
        if (date.after(this.getNotAfter()))
        {
            throw new CertificateExpiredException("certificate expired on " + c.getEndDate().getTime());
        }

        if (date.before(this.getNotBefore()))
        {
            throw new CertificateNotYetValidException("certificate not valid till " + c.getStartDate().getTime());
        }
    }

    public int getVersion()
    {
        return c.getVersion();
    }

    public BigInteger getSerialNumber()
    {
        return c.getSerialNumber().getValue();
    }

    public Principal getIssuerDN()
    {
        return new X509Principal(c.getIssuer());
    }

    public X500Principal getIssuerX500Principal()
    {
        try
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

            aOut.writeObject(c.getIssuer());

            return new X500Principal(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    public Principal getSubjectDN()
    {
        return new X509Principal(c.getSubject());
    }

    public X500Principal getSubjectX500Principal()
    {
        try
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

            aOut.writeObject(c.getSubject());

            return new X500Principal(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("can't encode issuer DN");
        }
    }

    public Date getNotBefore()
    {
        return c.getStartDate().getDate();
    }

    public Date getNotAfter()
    {
        return c.getEndDate().getDate();
    }

    public byte[] getTBSCertificate()
        throws CertificateEncodingException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);

        try
        {
            dOut.writeObject(c.getTBSCertificate());

            return bOut.toByteArray();
        }
        catch (IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public byte[] getSignature()
    {
        return c.getSignature().getBytes();
    }

    /**
     * return a more "meaningful" representation for the signature algorithm used in
     * the certficate.
     */
    public String getSigAlgName()
    {
        Provider    prov = Security.getProvider("BC");
        String      algName = prov.getProperty("Alg.Alias.Signature." + this.getSigAlgOID());

        if (algName != null)
        {
            return algName;
        }

        Provider[] provs = Security.getProviders();

        //
        // search every provider looking for a real algorithm
        //
        for (int i = 0; i != provs.length; i++)
        {
            algName = provs[i].getProperty("Alg.Alias.Signature." + this.getSigAlgOID());
            if (algName != null)
            {
                return algName;
            }
        }

        return this.getSigAlgOID();
    }

    /**
     * return the object identifier for the signature.
     */
    public String getSigAlgOID()
    {
        return c.getSignatureAlgorithm().getObjectId().getId();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    public byte[] getSigAlgParams()
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        if (c.getSignatureAlgorithm().getParameters() != null)
        {
            try
            {
                DEROutputStream         dOut = new DEROutputStream(bOut);

                dOut.writeObject(c.getSignatureAlgorithm().getParameters());
            }
            catch (Exception e)
            {
                throw new RuntimeException("exception getting sig parameters " + e);
            }

            return bOut.toByteArray();
        }
        return null;
    }

    public boolean[] getIssuerUniqueID()
    {
        DERBitString    id = c.getTBSCertificate().getIssuerUniqueId();

        if (id != null)
        {
            byte[]          bytes = id.getBytes();
            boolean[]       boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }
            
        return null;
    }

    public boolean[] getSubjectUniqueID()
    {
        DERBitString    id = c.getTBSCertificate().getSubjectUniqueId();

        if (id != null)
        {
            byte[]          bytes = id.getBytes();
            boolean[]       boolId = new boolean[bytes.length * 8 - id.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }
            
        return null;
    }

    public boolean[] getKeyUsage()
    {
        byte[]  bytes = this.getExtensionBytes("2.5.29.15");
        int     length = 0;

        if (bytes != null)
        {
            try
            {
                ASN1InputStream dIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
                DERBitString    bits = (DERBitString)dIn.readObject();

                bytes = bits.getBytes();
                length = (bytes.length * 8) - bits.getPadBits();
            }
            catch (Exception e)
            {
                throw new RuntimeException("error processing key usage extension");
            }

            boolean[]       keyUsage = new boolean[(length < 9) ? 9 : length];

            for (int i = 0; i != length; i++)
            {
                keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return keyUsage;
        }

        return null;
    }

    public List getExtendedKeyUsage() 
        throws CertificateParsingException
    {
        byte[]  bytes = this.getExtensionBytes("2.5.29.37");

        if (bytes != null)
        {
            try
            {
                ASN1InputStream dIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
                ASN1Sequence    seq = (ASN1Sequence)dIn.readObject();
                ArrayList       list = new ArrayList();

                for (int i = 0; i != seq.size(); i++)
                {
                    list.add(((DERObjectIdentifier)seq.getObjectAt(i)).getId());
                }
                
                return Collections.unmodifiableList(list);
            }
            catch (Exception e)
            {
                throw new CertificateParsingException("error processing extended key usage extension");
            }
        }

        return null;
    }
    
    public int getBasicConstraints()
    {
        byte[]  bytes = this.getExtensionBytes("2.5.29.19");

        if (bytes != null)
        {
            try
            {
                ASN1InputStream dIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
                ASN1Sequence    seq = (ASN1Sequence)dIn.readObject();

                if (seq.size() == 2)
                {
                    if (((DERBoolean)seq.getObjectAt(0)).isTrue())
                    {
                        return ((DERInteger)seq.getObjectAt(1)).getValue().intValue();
                    }
                    return -1;
                }
                else if (seq.size() == 1)
                {
                    if (seq.getObjectAt(0) instanceof DERBoolean)
                    {
                        if (((DERBoolean)seq.getObjectAt(0)).isTrue())
                        {
                            return Integer.MAX_VALUE;
                        }
                        return -1;
                    }
                    return -1;
                }
            }
            catch (Exception e)
            {
                throw new RuntimeException("error processing key usage extension");
            }
        }
        return -1;
    }

    public Set getCriticalExtensionOIDs() 
    {
        if (this.getVersion() == 3)
        {
            HashSet         set = new HashSet();
            X509Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    DERObjectIdentifier oid = (DERObjectIdentifier)e.nextElement();
                    X509Extension       ext = extensions.getExtension(oid);

                    if (ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    private byte[] getExtensionBytes(String oid)
    {
        X509Extensions exts = c.getTBSCertificate().getExtensions();

        if (exts != null)
        {
            X509Extension   ext = exts.getExtension(new DERObjectIdentifier(oid));
            if (ext != null)
            {
                return ext.getValue().getOctets();
            }
        }

        return null;
    }

    public byte[] getExtensionValue(String oid) 
    {
        X509Extensions exts = c.getTBSCertificate().getExtensions();

        if (exts != null)
        {
            X509Extension   ext = exts.getExtension(new DERObjectIdentifier(oid));

            if (ext != null)
            {
                ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
                DEROutputStream            dOut = new DEROutputStream(bOut);
                
                try
                {
                    dOut.writeObject(ext.getValue());

                    return bOut.toByteArray();
                }
                catch (Exception e)
                {
                    throw new RuntimeException("error encoding " + e.toString());
                }
            }
        }

        return null;
    }

    public Set getNonCriticalExtensionOIDs() 
    {
        if (this.getVersion() == 3)
        {
            HashSet         set = new HashSet();
            X509Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    DERObjectIdentifier oid = (DERObjectIdentifier)e.nextElement();
                    X509Extension       ext = extensions.getExtension(oid);

                    if (!ext.isCritical())
                    {
                        set.add(oid.getId());
                    }
                }

                return set;
            }
        }

        return null;
    }

    public boolean hasUnsupportedCriticalExtension()
    {
        if (this.getVersion() == 3)
        {
            X509Extensions  extensions = c.getTBSCertificate().getExtensions();

            if (extensions != null)
            {
                Enumeration     e = extensions.oids();

                while (e.hasMoreElements())
                {
                    DERObjectIdentifier oid = (DERObjectIdentifier)e.nextElement();
                    if (oid.getId().equals("2.5.29.15")
                       || oid.getId().equals("2.5.29.19"))
                    {
                        continue;
                    }

                    X509Extension       ext = extensions.getExtension(oid);

                    if (ext.isCritical())
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    static PublicKey createPublicKeyFromPublicKeyInfo(
            SubjectPublicKeyInfo         info)
    {
        AlgorithmIdentifier     algId = info.getAlgorithmId();
        
        if (algId.getObjectId().equals(PKCSObjectIdentifiers.rsaEncryption)
                || algId.getObjectId().equals(X509ObjectIdentifiers.id_ea_rsa))
        {
            return new ExtendedJCERSAPublicKey(info);
        }
        throw new RuntimeException("algorithm identifier in key not recognised");
    }
    public PublicKey getPublicKey()
    {
        return createPublicKeyFromPublicKeyInfo(c.getSubjectPublicKeyInfo());
    }

    public byte[] getEncoded()
        throws CertificateEncodingException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);

        try
        {
            dOut.writeObject(c);

            return bOut.toByteArray();
        }
        catch (IOException e)
        {
            throw new CertificateEncodingException(e.toString());
        }
    }

    public void setBagAttribute(
        DERObjectIdentifier oid,
        DEREncodable        attribute)
    {
        pkcs12Attributes.put(oid, attribute);
        pkcs12Ordering.addElement(oid);
    }

    public DEREncodable getBagAttribute(
        DERObjectIdentifier oid)
    {
        return (DEREncodable)pkcs12Attributes.get(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return pkcs12Ordering.elements();
    }

    public String toString()
    {
        StringBuffer    buf = new StringBuffer();
        String          nl = System.getProperty("line.separator");

        buf.append("  [0]         Version: " + this.getVersion() + nl);
        buf.append("         SerialNumber: " + this.getSerialNumber() + nl);
        buf.append("             IssuerDN: " + this.getIssuerDN() + nl);
        buf.append("           Start Date: " + this.getNotBefore() + nl);
        buf.append("           Final Date: " + this.getNotAfter() + nl);
        buf.append("            SubjectDN: " + this.getSubjectDN() + nl);
        buf.append("           Public Key: " + this.getPublicKey() + nl);
        buf.append("  Signature Algorithm: " + this.getSigAlgName() + nl);

        byte[]  sig = this.getSignature();

        buf.append("            Signature: " + new String(Hex.encode(sig, 0, 20)) + nl);
        for (int i = 20; i < sig.length; i += 20)
        {
            if (i < sig.length - 20)
            {
                buf.append("                       " + new String(Hex.encode(sig, i, 20)) + nl);
            }
            else
            {
                buf.append("                       " + new String(Hex.encode(sig, i, sig.length - i)) + nl);
            }
        }

        X509Extensions  extensions = c.getTBSCertificate().getExtensions();

        if (extensions != null)
        {
            Enumeration     e = extensions.oids();

            if (e.hasMoreElements())
            {
                buf.append("       Extensions: \n");
            }

            while (e.hasMoreElements())
            {
                DERObjectIdentifier     oid = (DERObjectIdentifier)e.nextElement();
                X509Extension           ext = extensions.getExtension(oid);

                if (ext.getValue() != null)
                {
                    byte[]                  octs = ext.getValue().getOctets();
                    ByteArrayInputStream    bIn = new ByteArrayInputStream(octs);
                    ASN1InputStream         dIn = new ASN1InputStream(bIn);
                    buf.append("                       critical(" + ext.isCritical() + ") ");
                    try
                    {
                        if (oid.equals(X509Extensions.BasicConstraints))
                        {
                            buf.append(new BasicConstraints((ASN1Sequence)dIn.readObject()) + nl);
                        }
                        else if (oid.equals(X509Extensions.KeyUsage))
                        {
                            buf.append(new KeyUsage((DERBitString)dIn.readObject()) + nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.netscapeCertType))
                        {
                            buf.append(new NetscapeCertType((DERBitString)dIn.readObject()) + nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.netscapeRevocationURL))
                        {
                            buf.append(new NetscapeRevocationURL((DERIA5String)dIn.readObject()) + nl);
                        }
                        else if (oid.equals(MiscObjectIdentifiers.verisignCzagExtension))
                        {
                            buf.append(new VerisignCzagExtension((DERIA5String)dIn.readObject()) + nl);
                        }
                        else 
                        {
                            buf.append(oid.getId());
                            buf.append(" value = " + ASN1Dump.dumpAsString(dIn.readObject()) + nl);
                            //buf.append(" value = " + "*****" + nl);
                        }
                    }
                    catch (Exception ex)
                    {
                        buf.append(oid.getId());
                   //     buf.append(" value = " + new String(Hex.encode(ext.getValue().getOctets())) + nl);
                        buf.append(" value = " + "*****" + nl);
                    }
                }
                else
                {
                    buf.append(nl);
                }
            }
        }

        return buf.toString();
    }

    public final void verify(
        PublicKey   key)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        Signature   signature = null;

        if (!c.getSignatureAlgorithm().equals(c.getTBSCertificate().getSignature()))
        {
            throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
        }

        try
        {
            signature = ExtendedX509V3CertificateGenerator.getSignature( c.getSignatureAlgorithm(),
                                                                         "BC" );
        }
        catch (Exception e2)
        {
            try {
                signature = ExtendedX509V3CertificateGenerator.getSignature( c.getSignatureAlgorithm(),
                                                                             null );
            } catch (InvalidParameterSpecException e) {
                throw new NoSuchAlgorithmException(e.getMessage());
            } catch (InvalidAlgorithmParameterException e) {
                throw new NoSuchAlgorithmException(e.getMessage());
            } catch (IOException e) {
                throw new NoSuchAlgorithmException(e.getMessage());
            }
        }

        signature.initVerify(key);

        signature.update(this.getTBSCertificate());

        if (!signature.verify(this.getSignature()))
        {
            throw new InvalidKeyException("Public key presented not for certificate signature");
        }
    }

    public final void verify(
        PublicKey   key,
        String      sigProvider)
        throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException
    {
        Signature signature;
        try {
            signature = ExtendedX509V3CertificateGenerator.getSignature( c.getSignatureAlgorithm(),
                                                                         sigProvider );
        } catch (InvalidParameterSpecException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        } catch (IOException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        }
        if (!c.getSignatureAlgorithm().equals(c.getTBSCertificate().getSignature()))
        {
            throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
        }
        
        signature.initVerify(key);

        signature.update(this.getTBSCertificate());

        if (!signature.verify(this.getSignature()))
        {
            throw new InvalidKeyException("Public key presented not for certificate signature");
        }
    }
}
