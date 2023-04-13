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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;


/**
 * <p><b>Java Serial Object File Merger</b>
 * <p>Is able to merge two (or more) java serial object files (such as result.ser) into one.
 *
 * @version $Id$
 */
public class SerObjectMerger extends ClientToolBox {

    @Override
    protected void execute(String[] args) {
        final List<String> argsList = new ArrayList<String>(Arrays.asList(args));
        argsList.remove(getName());
        if (argsList.isEmpty() || argsList.contains("help")) {
            System.out.println("Usage: SerObjectMerger file1.ser file2.ser ...");
            return;
        }
        if (argsList.size() == 1) {
            System.out.println("SerObjectMerger: you sure you want to merge a single file? Type 'help' for more information.");
            return;
        }
        try {
            System.out.println("SerObjectMerger: starting with reading " + argsList.size() + " files...");
            List<BigInteger> bigList = new ArrayList<BigInteger>();
            for (String fileName : argsList) {
                int duplicates = 0;
                int counterBI = 0;
                int counterOther = 0;
                try {
                    System.out.println(fileName + ": starting...");
                    ObjectInputStream oi = new ObjectInputStream(new FileInputStream(fileName));
                    while (true) {
                        Object obj = oi.readObject();
                        if (obj instanceof java.math.BigInteger) {
                            counterBI++;
                            BigInteger bi = (BigInteger) obj;
                            if (bigList.contains(bi)) {
                                duplicates++;
                            } else {
                                bigList.add(bi);
                            }
                        } else {
                            counterOther++;
                            System.out.println(fileName + ": this object is not a BigInteger: " + obj.getClass().getName());
                        }
                    }
                } catch (EOFException e) {
                    System.out.println(fileName +     ": Number of BigInteger objects: " + counterBI + ", duplicates: " + duplicates);
                    if (counterOther != 0) {
                        System.out.println(fileName + ": Count of other objects:       " + counterOther);
                    }
                }
            }
            System.out.println("SerObjectMerger: done with reading the files, sum: " + bigList.size());

            final String mergeFileName = new SimpleDateFormat("'merged-'yyyyMMdd-HH'h'mm'm'ss's.ser'").format(new Date());
            FileOutputStream fo = new FileOutputStream(new File(mergeFileName));
            ObjectOutputStream oos = new ObjectOutputStream(fo);

            for (Object obj : bigList) {
                oos.writeObject(obj);
            }
            oos.close();
            fo.close();
            System.out.println("SerObjectMerger: done with writing the merged file: " + mergeFileName);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return;
        }
    }

    @Override
    protected String getName() {
        return "SerObjectMerger";
    }
}
