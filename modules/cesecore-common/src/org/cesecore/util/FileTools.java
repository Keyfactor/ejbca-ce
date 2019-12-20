/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.cesecore.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.text.Collator;
import java.util.Arrays;
import java.util.Comparator;

import org.apache.log4j.Logger;


/**
 * Tools to handle some common file operations.
 *
 * @version $Id$
 */
public abstract class FileTools {
    private static final Logger log = Logger.getLogger(FileTools.class);

    private static final int ZIP_HEADER_SIZE = 4;
    /** Starting byte sequence of a ZIP file with at least one file */
    private static final byte[] ZIP_LOCAL_HEADER = new byte[] { 'P', 'K', 3, 4 };
    /** Starting byte sequence of an empty ZIP file */
    private static final byte[] ZIP_END_OF_CENTRAL_HEADER = new byte[] { 'P', 'K', 5, 6 };

    /**
     * Reads binary bytes from a PEM-file. The PEM-file may contain other stuff, the first item
     * between beginKey and endKey is read. Example: <code>-----BEGIN CERTIFICATE REQUEST-----
     * base64 encoded PKCS10 certification request -----END CERTIFICATE REQUEST----- </code>
     *
     * @param inbuf input buffer containing PEM-formatted stuff.
     * @param beginKey begin line of PEM message
     * @param endKey end line of PEM message
     *
     * @return byte[] containing binary Base64 decoded bytes.
     *
     * @throws IOException if the PEM file does not contain the right keys.
     */
    public static byte[] getBytesFromPEM(final byte[] inbuf, final String beginKey, final String endKey)
        throws IOException {
        final ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
        return getBytesFromPEM(instream, beginKey, endKey);
    } // getBytesfromPEM

    public static byte[] getBytesFromPEM(final InputStream instream, final String beginKey, final String endKey)
            throws IOException {
            if (log.isTraceEnabled()) {
                log.trace(">getBytesFromPEM");
            }

            final BufferedReader bufRdr = new BufferedReader(new InputStreamReader(instream));
            final ByteArrayOutputStream ostr = new ByteArrayOutputStream();
            final PrintStream opstr = new PrintStream(ostr);
            
            String temp;

            while (((temp = bufRdr.readLine()) != null) && !temp.equals(beginKey)) {
                continue;
            }

            if (temp == null) {
                throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
            }

            while (((temp = bufRdr.readLine()) != null) && !temp.equals(endKey)) {
                // Skip empty lines
                if (temp.trim().length() > 0) {
                    opstr.print(temp);
                }
            }

            if (temp == null) {
                throw new IOException("Error in input buffer, missing " + endKey + " boundary");
            }

            opstr.close();

            final byte[] bytes;
            try {
                bytes = Base64.decode(ostr.toByteArray());
            } catch (Exception e) {
                throw new IOException("Malformed PEM encoding or PEM of unknown type: " + e.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("<getBytesFromPEM");
            }
            return bytes;
        } // getBytesfromPEM

    /**
     * Helper function to read a file to a byte array.
     *
     * @param file filename of file.
     *
     * @return byte[] containing the contents of the file.
     * @throws FileNotFoundException if file was not found
     *
     * @throws FileNotFoundException if the file does not exist or cannot be read.
     */
    public static byte[] readFiletoBuffer(final String file) throws FileNotFoundException {
        final InputStream in = new FileInputStream(file);
        return readInputStreamtoBuffer(in);
    } 

    /**
     * Help function to read an InputStream to a byte array.
     *
     * @return byte[] containing the contents of the file.
     *
     */
    public static byte[] readInputStreamtoBuffer(final InputStream in)  {
        try (final ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            int len = 0;
            final byte[] buf = new byte[1024];
            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            in.close();
            return os.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Caught IOException for unknown reason", e);      
        }
    }

    /**
     * Sort the files by name with directories first.
     */
    public static void sortByName(final File[] files) {
    	if (files == null) {
    		return;
    	}
    	Arrays.sort(files, new FileComp());
    }
    
    private static class FileComp implements Comparator<File> {
    	private final Collator c = Collator.getInstance();

    	@Override
    	public int compare(final File f1, final File f2) {
    		if(f1 == f2) {
    			return 0;
    		}
    		if(f1.isDirectory() && f2.isFile()) {
    			return -1;
    		}
    		if(f1.isFile() && f2.isDirectory()) {
    			return 1;
    		}
    		return c.compare(f1.getName(), f2.getName());
    	}
    }
    
    public static File createTempDirectory() throws IOException {
        return createTempDirectory(null);
    }

    public static File createTempDirectory(File location) throws IOException {
        final File temp = File.createTempFile("tmp", Long.toString(System.nanoTime()), location);
        if (!(temp.delete())) {
            throw new IOException("Could not delete temp file: " + temp.getAbsolutePath());
        }
        //Known race condition exists here, not sure what an attacker would accomplish with it though
        if (!temp.mkdir()) {
            throw new IOException("Could not create temp directory: " + temp.getAbsolutePath());
        }
        return temp;
    }
    
    /**
     * Recursively deletes a file. If file is a directory, then it will delete all files and subdirectories contained.
     * 
     * @param file the file to delete
     */
    public static void delete(File file) {
        if (file.isDirectory()) {
            for (File subFile : file.listFiles()) {
                delete(subFile);
            }
        }
        if (!file.delete()) {
            log.error("Could not delete directory " + file.getAbsolutePath());
        }
    }
    
    /**
     * Copies the data from an input stream to an output stream. A limit on the file size is imposed.
     * 
     * @param input Stream to copy from.
     * @param output Stream to copy to.
     * @param maxBytes Throw a SizeLimitExceededException if more than this number of bytes are read.
     * @return The number of bytes copied.
     * @throws IOException If reading from or writing to the streams fail.
     * @throws StreamSizeLimitExceededException If more than maxBytes are read.
     */
    public static long streamCopyWithLimit(final InputStream input, final OutputStream output, final long maxBytes) throws IOException, StreamSizeLimitExceededException {
        if (maxBytes < 0 || (maxBytes == 0 && input.read() != -1)) {
            throw new StreamSizeLimitExceededException("Size limit was reached");
        } else if (maxBytes == 0) {
            return 0;
        }

        final byte[] buff = new byte[16*1024];
        long bytesCopied = 0;
        while (true) {
            int len = input.read(buff);
            if (len <= 0) { break; }
            bytesCopied += len;
            if (bytesCopied > maxBytes) {
                throw new StreamSizeLimitExceededException("Size limit was reached");
            }
            output.write(buff, 0, len);
        }
        
        return bytesCopied;
    }

    /**
     * Copies the data from an input stream to a byte array. A limit on the size is imposed.
     * More data than expectedSize or maxSize may be read from the stream.
     *
     * @param inputStream Input stream.
     * @param expectedSize Desired number of bytes to read, or -1 to read until end.
     * @param maxSize Maximum number of bytes to read, or -1 for no limit.
     * @return Byte array.
     * @throws StreamSizeLimitExceededException If the stream contained more bytes than maxSize or expectedSize.
     * @throws EOFException If there are not enough bytes in the stream.
     * @throws IOException If reading from the stream fails.
     */
    public static byte[] readStreamToByteArray(final InputStream inputStream, final int expectedSize, final int maxSize) throws StreamSizeLimitExceededException, IOException {
        final int expectedSizeBytes = expectedSize != -1 ? expectedSize : Integer.MAX_VALUE;
        final int maxSizeBytes = maxSize != -1 ? maxSize : Integer.MAX_VALUE;
        final int maxBytes = Math.min(expectedSizeBytes, maxSizeBytes);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(expectedSize != -1 ? expectedSize : 1024);
        final long bytesCopied = streamCopyWithLimit(inputStream, baos, maxBytes);
        if (bytesCopied < expectedSize) {
            throw new EOFException("Less file data than expected. Was " + bytesCopied + " but expected " + expectedSize);
        }
        return baos.toByteArray();
    }

    /**
     * Returns true if the given file data looks like a ZIP file based on the first bytes.
     * @param fileData File bytes.
     * @return true if it looks like a ZIP file
     */
    public static boolean isZipFile(final byte[] fileData) {
        final byte[] header = Arrays.copyOfRange(fileData, 0, ZIP_HEADER_SIZE);
        return Arrays.equals(header, ZIP_LOCAL_HEADER) || Arrays.equals(header, ZIP_END_OF_CENTRAL_HEADER);
    }

    /**
     * Returns true if the given file data looks like an empty ZIP file based on the first bytes.
     * @param fileData File bytes.
     * @return true if it looks like a ZIP file which is empty.
     */
    public static boolean isEmptyZipFile(final byte[] fileData) {
        final byte[] header = Arrays.copyOfRange(fileData, 0, ZIP_HEADER_SIZE);
        return Arrays.equals(header, ZIP_END_OF_CENTRAL_HEADER);
    }
}
