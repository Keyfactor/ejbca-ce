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

package org.ejbca.ui.cli;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * <p><b>Java Serial Object File Analyzer</b>
 * <p>Should tell us a bit of information about result.ser files that should help in using and developing the SerObjectMerger
 *
 * @version $Id$
 */
public class SerObjectAnalyzer extends ClientToolBox {

    @Override
    protected void execute(String[] args) {
        final List<String> argsList = new ArrayList<String>(Arrays.asList(args));
        argsList.remove(getName());
        if (argsList.isEmpty() || argsList.contains("help")) {
            System.out.println("Usage: SerObjectAnalyzer file1.ser ...");
            return;
        }

        int sum = 0;
        if (argsList.size() > 1) {
            System.out.println("SerObjectAnalyzer: starting with reading " + argsList.size() + " files...");
        }
        List<BigInteger> bigList = new ArrayList<BigInteger>();
        for (String fileName : argsList) {
            int counterBI = 0;
            int counterOther = 0;

            try {
                FileInputStream fi = new FileInputStream(fileName);
                ObjectInputStream oi = new ObjectInputStream(fi);
                while (true) {
                    Object obj = oi.readObject();
                    if (obj instanceof java.math.BigInteger) {
                        counterBI++;
                    } else {
                        counterOther++;
                        System.out.println(fileName + ": this object is not a BigInteger: " + obj.getClass().getName());
                    }
                }
            } catch (EOFException e) {
                System.out.println(fileName + ": Number of BigInteger objects: " + counterBI);
                if (counterOther != 0) {
                    System.out.println(fileName + ": Count of other objects:       " + counterOther);
                }
                sum += counterBI;
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("Exception occurred in file '" + fileName + "'");
                e.printStackTrace();
                return;
            }
        }
        if (argsList.size() > 1) {
            System.out.println("SerObjectAnalyzer: sum of all (duplicates not counted/detected): " + sum);
        }
    }

    @Override
    protected String getName() {
        return "SerObjectAnalyzer";
    }
}
