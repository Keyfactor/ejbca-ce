package org.cesecore.certificates.certificate.certextensions.standard;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * The SemanticsInformation object.
 * 
 * This class allows the usage of multiple semantics information OIDs.
 * 
 * RFC3039 (id-qcs-pkixQCSyntax-v1) / RFC3739 (id-qcs-pkixQCSyntax-v2) including multiple semantics 
 * information OIDs.
 * 
 * <pre>
 * qcStatement-2 QC-STATEMENT ::= { SYNTAX SemanticsInformation IDENTIFIED BY id-qcs-pkixQCSyntax-v2 }
 * --  This statement identifies conformance with requirements
 * --  defined in this Qualified Certificate profile
 * --  (Version 2). This statement may optionally contain
 * --  additional semantics information as specified below.
 *
 * SemanticsInformation ::= SEQUENCE {
 *      semanticsIdentifier         SemanticsIdentifiers OPTIONAL,
 *      nameRegistrationAuthorities NameRegistrationAuthorities OPTIONAL }
 *      (WITH COMPONENTS {..., semanticsIdentifiers PRESENT}|
 *      WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
 *
 * SemanticsIdentifiers ::=  SEQUENCE SIZE (1..MAX) OF GeneralName
 * NameRegistrationAuthorities ::=  SEQUENCE SIZE (1..MAX) OF OBJECT IDENTIFIER
 * </pre>
 */
public class ExtendedSemanticsInformation
    extends ASN1Object
{
    private List<ASN1ObjectIdentifier> semanticsIdentifier;
    private GeneralName[] nameRegistrationAuthorities;
    
    public static ExtendedSemanticsInformation getInstance(Object obj)
    {
        if (obj instanceof ExtendedSemanticsInformation)
        {
            return (ExtendedSemanticsInformation)obj;
        }

        if (obj != null)
        {
            return new ExtendedSemanticsInformation(ASN1Sequence.getInstance(obj));            
        }
        
        return null;
    }
        
    private ExtendedSemanticsInformation(ASN1Sequence seq)
    {
        @SuppressWarnings("rawtypes")
        Enumeration e = seq.getObjects();
        if (seq.size() < 1)
        {
             throw new IllegalArgumentException("no objects in SemanticsInformation");
        }
        
        semanticsIdentifier = new ArrayList<>();
        
        Object object = null;
        while (e.hasMoreElements() && (object = e.nextElement()) instanceof ASN1ObjectIdentifier)
        {
            semanticsIdentifier.add(ASN1ObjectIdentifier.getInstance(object));
        }
        
        if (e.hasMoreElements())
        {
            ASN1Sequence generalNameSeq = ASN1Sequence.getInstance(e.nextElement());
            nameRegistrationAuthorities = new GeneralName[generalNameSeq.size()];
            for (int i= 0; i < generalNameSeq.size(); i++)
            {
                nameRegistrationAuthorities[i] = GeneralName.getInstance(generalNameSeq.getObjectAt(i));
            } 
        }
    }
        
    public ExtendedSemanticsInformation(
        ASN1ObjectIdentifier semanticsIdentifier,
        GeneralName[] generalNames)
    {
    	if (semanticsIdentifier != null) {
    		this.semanticsIdentifier = new ArrayList<>();
    	    this.semanticsIdentifier.add(semanticsIdentifier);
    	}
        this.nameRegistrationAuthorities = cloneNames(generalNames);
    }
    
    public ExtendedSemanticsInformation(
            List<ASN1ObjectIdentifier> semanticsIdentifier,
            GeneralName[] generalNames)
    {
        this.semanticsIdentifier = semanticsIdentifier;
        this.nameRegistrationAuthorities = cloneNames(generalNames);
    }

    public ExtendedSemanticsInformation(ASN1ObjectIdentifier semanticsIdentifier)
    {
    	if (semanticsIdentifier != null) {
            this.semanticsIdentifier = new ArrayList<>();
            this.semanticsIdentifier.add(semanticsIdentifier);
        }
        this.nameRegistrationAuthorities = null;
    }
    
    public ExtendedSemanticsInformation(List<ASN1ObjectIdentifier> semanticsIdentifiers)
    {
        this.semanticsIdentifier = semanticsIdentifiers;
        this.nameRegistrationAuthorities = null;
    }

    public ExtendedSemanticsInformation(GeneralName[] generalNames)
    {
        this.semanticsIdentifier = null;
        this.nameRegistrationAuthorities = cloneNames(generalNames);
    }        
    
    public ASN1ObjectIdentifier getSemanticsIdentifier()
    {
        return (semanticsIdentifier != null && semanticsIdentifier.size() > 0) ? semanticsIdentifier.get(0) : null;
    }
    
    public List<ASN1ObjectIdentifier> getSemanticsIdentifiers()
    {
        return semanticsIdentifier;
    }
        
    public GeneralName[] getNameRegistrationAuthorities()
    {
        return cloneNames(nameRegistrationAuthorities);
    } 
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector(2);
        
        for (ASN1ObjectIdentifier oid : semanticsIdentifier)
        {
            seq.add(oid);
        }
        
        
        if (this.nameRegistrationAuthorities != null)
        {
            seq.add(new DERSequence(nameRegistrationAuthorities));
        }            

        return new DERSequence(seq);
    }

    private static GeneralName[] cloneNames(GeneralName[] names)
    {
        if (names != null)
        {
            GeneralName[] tmp = new GeneralName[names.length];

            System.arraycopy(names, 0, tmp, 0, names.length);

            return tmp;
        }
        return null;
    }
}
