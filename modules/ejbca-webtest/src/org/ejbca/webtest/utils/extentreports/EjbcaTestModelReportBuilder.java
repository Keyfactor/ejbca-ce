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
package org.ejbca.webtest.utils.extentreports;

import java.io.IOException;

import com.aventstack.extentreports.ExtentTest;
import com.aventstack.extentreports.GherkinKeyword;
import com.aventstack.extentreports.MediaEntityBuilder;
import com.aventstack.extentreports.MediaEntityModelProvider;
import com.aventstack.extentreports.convert.TestModelReportBuilder;
import com.aventstack.extentreports.model.AbstractStructure;
import com.aventstack.extentreports.model.Log;
import com.aventstack.extentreports.model.ScreenCapture;
import com.aventstack.extentreports.model.Test;

/**
 * Custom implementation of TestModelReportBuilder to restore screenshot(s) within log events from JSON file.
 *
 * @version $Id$
 */
public class EjbcaTestModelReportBuilder extends TestModelReportBuilder {

    @Override
    public void createDomain(Test test, ExtentTest extentTest) throws ClassNotFoundException {
        extentTest.getModel().setStartTime(test.getStartTime());
        extentTest.getModel().setEndTime(test.getEndTime());
        extentTest.getModel().computeEndTimeFromChildren();
        // create events
        for (Log log : test.getLogContext().getAll()) {
            if (log.getDetails() != null) {
                if(log.getScreenCaptureContext().isEmpty()) {
                    extentTest.log(log.getStatus(), log.getDetails());
                }
                else {
                    extentTest.log(log.getStatus(), log.getDetails(), getMediaEntityModelProvider(log.getScreenCaptureContext()));
                }
            }
            if (log.getExceptionInfo() != null) {
                if(log.getScreenCaptureContext().isEmpty()) {
                    extentTest.log(log.getStatus(), log.getExceptionInfo());
                }
                else {
                    extentTest.log(log.getStatus(), log.getExceptionInfo().getThrowable(), getMediaEntityModelProvider(log.getScreenCaptureContext()));
                }
            }

        }
        // assign attributes
        test.getAuthorContext().getAll().forEach(x -> extentTest.assignAuthor(x.getName()));
        test.getCategoryContext().getAll().forEach(x -> extentTest.assignCategory(x.getName()));
        test.getDeviceContext().getAll().forEach(x -> extentTest.assignDevice(x.getName()));
        // handle nodes
        for (Test node : test.getNodeContext().getAll()) {
            ExtentTest extentNode;
            if (node.getBehaviorDrivenTypeName() == null) {
                extentNode = extentTest.createNode(node.getName(), node.getDescription());
            } else {
                extentNode = extentTest.createNode(new GherkinKeyword(node.getBehaviorDrivenTypeName()), node.getName(),
                        node.getDescription());
            }
            createDomain(node, extentNode);
        }
    }

    private MediaEntityModelProvider getMediaEntityModelProvider(final AbstractStructure<ScreenCapture> screenCaptures) {
        try {
            return MediaEntityBuilder.createScreenCaptureFromBase64String(screenCaptures.getFirst().getBase64String()).build();
        }
        catch (IOException ioex) {
            throw new RuntimeException("Cannot handle ScreenCapture.");
        }
    }
}
