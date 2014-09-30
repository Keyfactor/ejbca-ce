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
 
package org.cesecore.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
        if (log.isTraceEnabled()) {
            log.trace(">getBytesFromPEM");
        }

        final ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
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

        final byte[] bytes = Base64.decode(ostr.toByteArray());
        if (log.isTraceEnabled()) {
            log.trace("<getBytesFromPEM");
        }
        return bytes;
    } // getBytesfromPEM

    /**
     * Helpfunction to read a file to a byte array.
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
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
        int len = 0;
        final byte[] buf = new byte[1024];
        while ((len = in.read(buf)) > 0) {
            os.write(buf, 0, len);
        }
        in.close();
        os.close();
        return os.toByteArray();
        } catch(IOException e) {
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
} 
