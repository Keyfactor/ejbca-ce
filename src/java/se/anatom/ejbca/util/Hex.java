/*
 * Copyright 1998-2000 Sun Microsystems, Inc. All Rights Reserved.
 *
 * Modified by Tomas Gustavsson
 */
package se.anatom.ejbca.util;

import java.io.*;

import java.math.BigInteger;


/**
 * This class implements a hex decoder, decoding a string with hex-characters into the binary form.
 *
 * @version $Id: Hex.java,v 1.3 2003-06-26 11:43:25 anatom Exp $
 */
public class Hex {
    private static final char[] hex = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /**
     * Encodar binärt till hex
     *
     * @param dataStr bin-representation av data
     *
     * @return Hex-representation av data
     */
    public static String encode(byte[] dataStr) {
        if (dataStr == null) {
            return null;
        }

        StringWriter w = new StringWriter();

        for (int i = 0; i < dataStr.length; i++) {
            int b = dataStr[i];
            w.write(hex[((b >> 4) & 0xF)]);
            w.write(hex[((b >> 0) & 0xF)]);
        }

        return w.toString();
    }

    /**
     * Decodar hex till binärt
     *
     * @param dataStr Sträng innehållande hex-representation av data
     *
     * @return byte[] innhållande binär representation av data
     */
    public static byte[] decode(String dataStr) {
        if (dataStr == null) {
            return null;
        }

        if ((dataStr.length() & 0x01) == 0x01) {
            dataStr = new String(dataStr + "0");
        }

        BigInteger cI = new BigInteger(dataStr, 16);
        byte[] data = cI.toByteArray();

        return data;
    }
     //decode

    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: HexStrToBin enc/dec <infileName> <outfilename>");
            System.exit(1);
        }

        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            InputStream in = new FileInputStream(args[1]);
            int len = 0;
            byte[] buf = new byte[1024];

            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }

            in.close();
            os.close();

            byte[] data = null;

            if (args[0].equals("dec")) {
                data = decode(os.toString());
            } else {
                String strData = encode(os.toByteArray());
                data = strData.getBytes();
            }

            FileOutputStream fos = new FileOutputStream(args[2]);
            fos.write(data);
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
     //main
}
 // Hex
