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

package com.keyfactor.util;

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

/** Basically it checks the stream for things with a negative length (this is what represents indefinite-length encoding).
 * It doesn't do a very thorough job as ideally you'd identify constructed objects and iterate through their content as well.
 * Usage:

 * try (IndefiniteLengthDetectorStream ildStream = new IndefiniteLengthDetectorStream(bain2)) {
 *     while (ildStream.readValue() != null)
 *     {
 *         ;
 *     }
 *     assertFalse("ks.store() with PKCS12StoreParameter(true) is expected to not have indefinitlength encoding", ildStream.isIndefiniteLength());
 * }
 */
public class IndefiniteLengthDetectorStream
    extends FilterInputStream {
    private boolean isIndefiniteLength = false;

    public IndefiniteLengthDetectorStream(InputStream input) {
        super(input);
    }

    static int readTagNumber(InputStream s, int tag)
        throws IOException {
        int tagNo = tag & 0x1f;

        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagNo == 0x1f) {
            int b = s.read();
            if (b < 31) {
                if (b < 0) {
                    throw new EOFException("EOF found inside tag value.");
                }
                throw new IOException("corrupted stream - high tag number < 31 found");
            }
            tagNo = b & 0x7f;
            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if (0 == tagNo) {
                throw new IOException("corrupted stream - invalid high tag number found");
            }
            while ((b & 0x80) != 0) {
                if ((tagNo >>> 24) != 0) {
                    throw new IOException("Tag number more than 31 bits");
                }
                tagNo <<= 7;
                b = s.read();
                if (b < 0) {
                    throw new EOFException("EOF found inside tag value.");
                }
                tagNo |= (b & 0x7f);
            }
        }
        return tagNo;
    }

    static int readLength(InputStream s)
        throws IOException {
        int length = s.read();
        if (0 == (length >>> 7)) {
            // definite-length short form
            return length;
        }
        if (0x80 == length) {
            // indefinite-length
            return -1;
        }
        if (length < 0) {
            throw new EOFException("EOF found when length expected");
        }
        if (0xFF == length) {
            throw new IOException("invalid long form definite-length 0xFF");
        }
        int octetsCount = length & 0x7F, octetsPos = 0;
        length = 0;
        do {
            int octet = s.read();
            if (octet < 0) {
                throw new EOFException("EOF found reading length");
            }
            if ((length >>> 23) != 0) {
                throw new IOException("long form definite-length more than 31 bits");
            }
            length = (length << 8) + octet;
        }
        while (++octetsPos < octetsCount);
        return length;
    }

    /**
     * @return non-null for definite length data, null for indefinite length or EOF.
     * @throws IOException
     */
    public byte[] readValue()
        throws IOException {
        int tag = read();
        if (tag <= 0) {
            if (tag == 0) {
                throw new IOException("unexpected end-of-contents marker");
            }
            return null;
        }

        readTagNumber(this, tag); // pull tagNo from the stream but we don't need it here
        int length = readLength(this);
        if (length < 0) {
            isIndefiniteLength = true;
            return null;
        }
        byte[] data = new byte[length];
        Streams.readFully(this, data);
        return data;
    }

    /**
     * @return true if the detector encountered an indefinite length object
     */
    public boolean isIndefiniteLength() {
        return this.isIndefiniteLength;
    }
}
