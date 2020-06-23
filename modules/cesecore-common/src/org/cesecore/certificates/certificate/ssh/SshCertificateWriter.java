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

package org.cesecore.certificates.certificate.ssh;

/**
 * @version $Id$
 *
 */

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class SshCertificateWriter extends ByteArrayOutputStream {
    private static String CHARSET_ENCODING = "UTF8";

    public SshCertificateWriter() {
    }

    public SshCertificateWriter(int length) {
        super(length);
    }

    public byte[] array() {
        return this.buf;
    }

    public void move(int numBytes) {
        this.count += numBytes;
    }

    public void writeBigInteger(BigInteger bi) throws IOException {
        byte[] raw = bi.toByteArray();
        writeInt(raw.length);
        write(raw);
    }

    public void writeBoolean(boolean b) {
        write(b ? 1 : 0);
    }

    public void writeByteArray(byte[] data) throws IOException {
        if (data == null) {
            writeInt(0);
        } else {
            writeBinaryString(data, 0, data.length);
        }
    }

    public void writeBinaryString(byte[] data, int offset, int len) throws IOException {
        if (data == null) {
            writeInt(0);
        } else {
            writeInt(len);
            write(data, offset, len);
        }
    }

    public void writeInt(int value) throws IOException {
        byte[] raw = new byte[4];
        raw[0] = (byte) (value >> 24);
        raw[1] = (byte) (value >> 16);
        raw[2] = (byte) (value >> 8);
        raw[3] = (byte) value;
        write(raw);
    }

    
    public void writeLong(long value) throws IOException {
        byte[] raw = new byte[8];
        raw[0] = (byte) (value >> 56);
        raw[1] = (byte) (value >> 48);
        raw[2] = (byte) (value >> 40);
        raw[3] = (byte) (value >> 32);
        raw[4] = (byte) (value >> 24);
        raw[5] = (byte) (value >> 16);
        raw[6] = (byte) (value >> 8);
        raw[7] = (byte) value;
        write(raw);
    }

    public void writeString(String str) throws IOException {
        writeString(str, CHARSET_ENCODING);
    }

    public void writeString(String str, String charset) throws IOException {
        if (str == null) {
            writeInt(0);
        } else {
            byte[] tmp = str.getBytes(charset);
            writeInt(tmp.length);
            write(tmp);
        }
    }

    public void silentClose() {
        try {
            close();
        } catch (IOException iOException) {
        }
    }

}
