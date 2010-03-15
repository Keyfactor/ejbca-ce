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

package org.ejbca.ui.web;

import java.io.IOException;
import java.io.InputStream;

/**
 * Private inner class which represents an input stream with controlled
 * output.
 * 
 * @author mikek
 * @version $Id: LimitLengthASN1ReaderTest.java 8739 2010-03-12 12:01:49Z anatom $
 */
class InputStreamStub extends InputStream {

    private int[] contents;
    private int counter = 0;

    public InputStreamStub(int[] contents) {
	super();
	this.contents = contents;
    }

    public int read() throws IOException {
	if (contents == null) {
	    throw new NullPointerException("Class member contents must be set for anonymous inner class.");
	}
	if (counter < contents.length) {
	    return contents[counter++];
	} else {
	    return -1;
	}
    }
}