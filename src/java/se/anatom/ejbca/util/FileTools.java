
package se.anatom.ejbca.util;

import java.io.*;

import org.apache.log4j.*;

import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.Hex;

/**
 * Tools to handle some common file operations.
 *
 * @version $Id: FileTools.java,v 1.1.1.1 2001-11-15 14:58:19 anatom Exp $
 */
public class FileTools {

    private static Category cat = Category.getInstance(FileTools.class.getName());

    /** Creates new FileTools */
    public FileTools() {
    }

    /**
     * Reads binary bytes from a PEM-file. The PEM-file may contain other stuff,
     * the first item between beginKey and endKey is read.
     * <p>Example:
     *<pre>
     *-----BEGIN CERTIFICATE REQUEST-----
     *<base64 encoded PKCS10 certification request>
     *-----END CERTIFICATE REQUEST-----
     *
     * @param inbuf input buffer containing PEM-formatted stuff.
     * @return byte[] containing binary Base64 decoded bytes.
     * @exception IOException if the PEM file does not contain the right keys.
     */
    public static byte[] getBytesFromPEM(byte[] inbuf, String beginKey, String endKey)
    throws IOException {
        cat.debug(">getBytesFromPEM");

        ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
        BufferedReader bufRdr = new BufferedReader(new InputStreamReader(instream));
        ByteArrayOutputStream ostr = new ByteArrayOutputStream();
        PrintStream opstr = new PrintStream(ostr);
        String temp;
        while ((temp = bufRdr.readLine()) != null &&
        !temp.equals(beginKey))
            continue;
        if (temp == null)
            throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
        while ((temp = bufRdr.readLine()) != null &&
        !temp.equals(endKey))
            opstr.print(temp);
        if (temp == null)
            throw new IOException("Error in input buffer, missing " + endKey + " boundary");
        opstr.close();

        byte[] bytes = Base64.decode(ostr.toByteArray());

        cat.debug("<getBytesFromPEM");
        return bytes;
    } // getBytesfromPEM

    /**
     * Helpfunction to read a file to a byte array.
     *
     *@param file filename of file.
     *@return byte[] containing the contents of the file.
     *@exception IOException if the file does not exist or cannot be read.
     **/
    public static byte[] readFiletoBuffer(String file) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        InputStream in = new FileInputStream(file);
        int len = 0;
        byte buf[] = new byte[1024];
        while ((len = in.read(buf)) > 0)
            os.write(buf, 0, len);
        in.close();
        os.close();
        return os.toByteArray();
    } // readFiletoBuffer

} // FileTools

