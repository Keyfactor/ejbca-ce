/*
 * Copyright (c) 2009-2010 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * This class represents the SCEP <code>IssuerAndSubject</code> ASN.1 object.
 * 
 * This object is defined by the following ASN.1 notation:
 *
 * <pre>
 * IssuerAndSubject ::= SEQUENCE {
 *     issuer Name,
 *     subject Name,
 * }
 * </pre>
 *
 * @author David Grant
 */
public final class IssuerAndSubject extends ASN1Object {
    /**
     * The issuer name.
     */
    private final X500Name issuer;
    /**
     * The subject name.
     */
    private final X500Name subject;

    /**
     * Creates a new instance of this class from the given sequence.
     *
     * @param seq
     *            the sequence.
     */
    public IssuerAndSubject(final ASN1Sequence seq) {
        issuer = X500Name.getInstance(seq.getObjectAt(0));
        subject = X500Name.getInstance(seq.getObjectAt(1));
    }

    /**
     * Creates a new instance of this class using the given issuer and subject.
     *
     * @param issuer
     *            the issuer.
     * @param subject
     *            the subject.
     */
    public IssuerAndSubject(final X500Name issuer, final X500Name subject) {
        this.issuer = issuer;
        this.subject = subject;
    }

    /**
     * Creates a new instance of this class using the given byte array.
     *
     * @param bytes
     *            the byte array.
     */
    public IssuerAndSubject(final byte[] bytes) {
        this(ASN1Sequence.getInstance(bytes));
    }

    /**
     * Returns the issuer.
     *
     * @return the issuer.
     */
    public X500Name getIssuer() {
        return issuer;
    }

    /**
     * Returns the subject.
     *
     * @return the subject.
     */
    public X500Name getSubject() {
        return subject;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(issuer);
        v.add(subject);

        return new DERSequence(v);
    }
}
