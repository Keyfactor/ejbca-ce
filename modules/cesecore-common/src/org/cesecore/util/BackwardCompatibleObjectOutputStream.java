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
package org.cesecore.util;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * An extended ObjectOutputStream that allows classes to be renamed before serializing them.
 */
public class BackwardCompatibleObjectOutputStream extends ObjectOutputStream {

    private static final Logger log = Logger.getLogger(BackwardCompatibleObjectOutputStream.class);

    private SerializedStringReplacingOutputStream replacingOutputStream;
    private Map<String, String> renameMap = null;

    /**
     * An OutputStream that can replace a serialized string at a given point.
     * This is used to replace class name strings with old backward-compatible names.
     */
    public static class SerializedStringReplacingOutputStream extends OutputStream {
        private final OutputStream os;
        private boolean replacing = false;
        private int replacementOffset;
        private int bytesToSkip;
        private String replacementString;

        private byte originalLengthHighByte;

        public SerializedStringReplacingOutputStream(final OutputStream os) {
            this.os = os;
        }

        @Override
        public void write(int b) throws IOException {
            if (!replacing) {
                os.write(b);
            } else {
                writeWithReplacement(b);
            }
        }

        private void writeWithReplacement(int b) throws IOException {
            if (replacementOffset == 0) {
                // The string length is two bytes, in big-endian byte order.
                originalLengthHighByte = (byte)b;
            } else if (replacementOffset == 1) {
                int oldLength = originalLengthHighByte<<8 | (byte)b;
                bytesToSkip = oldLength;
                final byte[] newStringBytes = replacementString.getBytes(StandardCharsets.UTF_8);
                os.write((newStringBytes.length >>> 8) & 0xFF);
                os.write(newStringBytes.length & 0xFF);
                os.write(newStringBytes);
            } else if (bytesToSkip > 0) {
                bytesToSkip--;
            } else {
                replacing = false;
                os.write(b);
            }
            replacementOffset++;
        }

        /**
         * Activates replacement of the next serialized string with the given string.
         */
        public void replaceNextString(final String newStringValue) {
            replacing = true;
            replacementOffset = 0;
            replacementString = newStringValue;
        }
    }

    private BackwardCompatibleObjectOutputStream(final SerializedStringReplacingOutputStream replacingOut) throws IOException {
        super(replacingOut);
    }

    // Can't do this in a constructor :(
    public static BackwardCompatibleObjectOutputStream create(final OutputStream out) throws IOException {
        final SerializedStringReplacingOutputStream replacingOut = new SerializedStringReplacingOutputStream(out);
        final BackwardCompatibleObjectOutputStream res = new BackwardCompatibleObjectOutputStream(replacingOut);
        res.replacingOutputStream = replacingOut;
        return res;
    }

    public void setRenamedClasses(final Map<String, String> renameMap) {
        this.renameMap = renameMap;
    }

    @Override
    protected void writeClassDescriptor(ObjectStreamClass desc) throws IOException {
        if (renameMap != null) {
            final String backwardCompatibleName = renameMap.get(desc.getName());
            if (backwardCompatibleName != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Replacing class name in serialization with backward-compatible class name. " + desc.getName() + " --> " + backwardCompatibleName);
                }
                flush();
                replacingOutputStream.replaceNextString(backwardCompatibleName);
            }
        }
        super.writeClassDescriptor(desc);
    }

}
