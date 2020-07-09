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

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

/**
 * SSH Certificate Reader.
 *
 * @version $Id$
 */
public class SshCertificateReader extends ByteArrayInputStream {

    private static final String DEFAULT_CHARSET_ENCODING = "UTF8";
    private static String CHARSET_ENCODING = "UTF8";

    public static boolean encode;

    static {
        setCharsetEncoding(CHARSET_ENCODING);
    }

    public SshCertificateReader(byte[] buffer) {
        super(buffer, 0, buffer.length);
    }

    /**
     * Provides access to the underlying array
     * @return byte[]
     */
    public byte[] array() {
        return this.buf;
    }

    /**
     * Allows the default encoding to be overridden for String variables processed
     * by the class. This currently defaults to UTF-8.
     *
     * @param charset characters encoding.
     */
    public static void setCharsetEncoding(String charset) {
        try {
            // Test charset
            "123456890".getBytes(charset);
            CHARSET_ENCODING = charset;
            encode = true;
        } catch (UnsupportedEncodingException ex) {
            // Reset the encoding to default
            CHARSET_ENCODING = DEFAULT_CHARSET_ENCODING;
            encode = false;
        }
    }

    /**
     * Read until the buffer supplied is full.
     * @param b buffer
     * @param off offset
     * @param len length
     * @throws IOException IO exception.
     */
    public void readFully(byte b[], int off, int len) throws IOException {
        if (len < 0) {
            throw new IndexOutOfBoundsException();
        }
        int n = 0;
        while (n < len) {
            int count = read(b, off + n, len - n);
            if (count < 0) {
                throw new EOFException(
                        "Could not read number of bytes requested: " + len + ", got " + n + " into buffer size " + b.length + " at offset " + off);
            }
            n += count;
        }
    }

    /**
     * Write a boolean value to the array.
     */
    public boolean readBoolean() {
        return read() == 1;
    }

    public void readFully(byte[] b) throws IOException {
        readFully(b, 0, b.length);
    }

    /**
     * Read a BigInteger from the array.
     * @return the BigInteger value.
     * @throws IOException IO exception.
     */
    public BigInteger readBigInteger() throws IOException {
        int len = (int) readInt();
        byte[] raw = new byte[len];
        readFully(raw);
        return new BigInteger(raw);
    }

    /**
     * Read an integer (4 bytes) from the array. This is returned as a long
     * as we deal with unsigned ints so the value may be higher than the
     * standard java int.
     * @param data data
     * @param start start position
     * @return the value represent by a long.
     */
    public static long readInt(byte[] data, int start) {
        return (((long) (data[start] & 0xFF) << 24) & 0xFFFFFFFFL) | ((data[start + 1] & 0xFF) << 16) | ((data[start + 2] & 0xFF) << 8)
                | ((data[start + 3] & 0xFF) << 0);
    }

    /**
     * Read an array of bytes from the array.
     * @return the byte array.
     * @throws IOException IO exception.
     */
    public byte[] readByteArray() throws IOException {
        int len = (int) readInt();
        byte[] buf = new byte[len];
        readFully(buf);
        return buf;
    }

    /**
     * Read an integer (4 bytes) from the array. This is returned as a long
     * as we deal with unsigned ints so the value may be higher than the
     * standard java int.
     * @return the integer value as a long.
     * @throws IOException IO exception.
     */
    public long readInt() throws IOException {
        int ch1 = read();
        int ch2 = read();
        int ch3 = read();
        int ch4 = read();
        if ((ch1 | ch2 | ch3 | ch4) < 0)
            throw new EOFException();
        return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4)) & 0xFFFFFFFFL;
    }

    /**
     * Read a String from the array.
     * @return the String value.
     * @throws IOException IO exception.
     */
    public String readString() throws IOException {
        return readString(CHARSET_ENCODING);
    }

    /**
     * Read a String from the array converting using the given character set.
     * @param charset characters encoding.
     * @return a String from the array converting using the given character set.
     * @throws IOException IO exception.
     */
    public String readString(String charset) throws IOException {
        long len = readInt();

        if (len > available()) {
            throw new IOException("Cannot read string of length " + len + " bytes when only " + available() + " bytes are available");
        }

        byte[] raw = new byte[(int) len];
        readFully(raw);
        if (encode) {
            return new String(raw, charset);
        }
        return new String(raw);

    }

    public long readLong() throws IOException {
        long ch1 = read();
        long ch2 = read();
        long ch3 = read();
        long ch4 = read();
        long ch5 = read();
        long ch6 = read();
        long ch7 = read();
        long ch8 = read();
        if ((ch1 | ch2 | ch3 | ch4 | ch5 | ch6 | ch7 | ch8) < 0) {
            throw new EOFException();
        }
        return ((ch1 << 56) + (ch2 << 48) + (ch3 << 40) + (ch4 << 32) + (ch5 << 24) + (ch6 << 16) + (ch7 << 8) + (ch8 << 0)) & 0xFFFFFFFFFFFFFFFFL;
    }


    public void close() {
        try {
            super.close();
        } catch (IOException e) {
            // Silent
        }
    }
}
