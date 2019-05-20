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
package org.ejbca.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.awt.print.PageFormat;
import java.awt.print.Paper;
import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.io.IOException;
import java.io.StringReader;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.junit.Test;

/**
 * Tests SVGImageManipulator by generating an image.
 * The output may vary slightly from system to system, so we only check that the result is not null in the test.
 * The test prints the image in raw data format as Base64, so it can be checked manually.
 * 
 * @version $Id$
 */
public class SVGImageManipulatorUnitTest {

    private static final Logger log = Logger.getLogger(SVGImageManipulatorUnitTest.class);

    /** Basic SVG with some attributes ($USERNAME, $ENDDATE, etc) */
    private static final String TEST_SVG =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" + 
            "<svg\n" + 
            "   xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n" + 
            "   xmlns:cc=\"http://creativecommons.org/ns#\"\n" + 
            "   xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"\n" + 
            "   xmlns:svg=\"http://www.w3.org/2000/svg\"\n" + 
            "   xmlns=\"http://www.w3.org/2000/svg\"\n" + 
            "   id=\"svg8\"\n" + 
            "   version=\"1.1\"\n" + 
            "   viewBox=\"0 0 85.599998 53.98\"\n" + 
            "   height=\"53.98mm\"\n" + 
            "   width=\"85.599998mm\">\n" + 
            "  <defs\n" + 
            "     id=\"defs2\" />\n" + 
            "  <metadata\n" + 
            "     id=\"metadata5\">\n" + 
            "    <rdf:RDF>\n" + 
            "      <cc:Work\n" + 
            "         rdf:about=\"\">\n" + 
            "        <dc:format>image/svg+xml</dc:format>\n" + 
            "        <dc:type\n" + 
            "           rdf:resource=\"http://purl.org/dc/dcmitype/StillImage\" />\n" + 
            "        <dc:title></dc:title>\n" + 
            "      </cc:Work>\n" + 
            "    </rdf:RDF>\n" + 
            "  </metadata>\n" + 
            "  <g\n" + 
            "     transform=\"translate(0,-243.02)\"\n" + 
            "     id=\"layer1\">\n" + 
            "    <text\n" + 
            "       id=\"text3723\"\n" + 
            "       y=\"251.83145\"\n" + 
            "       x=\"3.6081383\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:bold;font-stretch:normal;font-size:5.64444444px;line-height:1.25;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Bold';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332;\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:bold;font-stretch:normal;font-size:5.64444444px;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Bold';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr;text-anchor:start;stroke-width:0.26458332;\"\n" + 
            "         y=\"251.83145\"\n" + 
            "         x=\"3.6081383\"\n" + 
            "         id=\"tspan3721\">User:</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3727\"\n" + 
            "       y=\"251.43054\"\n" + 
            "       x=\"30.735998\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:bold;font-stretch:normal;font-size:5.64444444px;line-height:1.25;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Bold';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332;\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:bold;font-stretch:normal;font-size:5.64444444px;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Bold';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr;text-anchor:start;stroke-width:0.26458332;\"\n" + 
            "         y=\"251.43054\"\n" + 
            "         x=\"30.735998\"\n" + 
            "         id=\"tspan3725\">$USERNAME</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3731\"\n" + 
            "       y=\"261.98767\"\n" + 
            "       x=\"3.6081386\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;line-height:1.25;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr-tb;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr-tb;text-anchor:start;stroke-width:0.26458332\"\n" + 
            "         y=\"261.98767\"\n" + 
            "         x=\"3.6081386\"\n" + 
            "         id=\"tspan3729\">CN:</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3735\"\n" + 
            "       y=\"262.12131\"\n" + 
            "       x=\"30.869627\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;line-height:1.25;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr-tb;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr-tb;text-anchor:start;stroke-width:0.26458332\"\n" + 
            "         y=\"262.12131\"\n" + 
            "         x=\"30.869627\"\n" + 
            "         id=\"tspan3733\">$CN</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3739\"\n" + 
            "       y=\"272.94571\"\n" + 
            "       x=\"3.474504\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;line-height:1.25;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr-tb;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr-tb;text-anchor:start;stroke-width:0.26458332\"\n" + 
            "         y=\"272.94571\"\n" + 
            "         x=\"3.474504\"\n" + 
            "         id=\"tspan3737\">Expires:</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3743\"\n" + 
            "       y=\"272.54483\"\n" + 
            "       x=\"30.735991\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;line-height:1.25;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr-tb;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr-tb;text-anchor:start;stroke-width:0.26458332\"\n" + 
            "         y=\"272.54483\"\n" + 
            "         x=\"30.735991\"\n" + 
            "         id=\"tspan3741\">$ENDDATE</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3747\"\n" + 
            "       y=\"284.17105\"\n" + 
            "       x=\"3.6081383\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;line-height:1.25;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr-tb;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr-tb;text-anchor:start;stroke-width:0.26458332\"\n" + 
            "         y=\"284.17105\"\n" + 
            "         x=\"3.6081383\"\n" + 
            "         id=\"tspan3745\">PIN:</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3751\"\n" + 
            "       y=\"283.90378\"\n" + 
            "       x=\"30.735998\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444444px;line-height:1.25;font-family:monospace;-inkscape-font-specification:'monospace, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332;\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444444px;font-family:monospace;-inkscape-font-specification:'monospace, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr;text-anchor:start;stroke-width:0.26458332;\"\n" + 
            "         y=\"283.90378\"\n" + 
            "         x=\"30.735998\"\n" + 
            "         id=\"tspan3749\">$PIN1</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3755\"\n" + 
            "       y=\"293.25821\"\n" + 
            "       x=\"3.6081388\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;line-height:1.25;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr-tb;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:5.64444447px;font-family:sans-serif;-inkscape-font-specification:'sans-serif, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr-tb;text-anchor:start;stroke-width:0.26458332\"\n" + 
            "         y=\"293.25821\"\n" + 
            "         x=\"3.6081388\"\n" + 
            "         id=\"tspan3753\">PUK:</tspan></text>\n" + 
            "    <text\n" + 
            "       id=\"text3759\"\n" + 
            "       y=\"293.79272\"\n" + 
            "       x=\"30.735996\"\n" + 
            "       style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:4.93888889px;line-height:1.25;font-family:monospace;-inkscape-font-specification:'monospace, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;letter-spacing:0px;word-spacing:0px;writing-mode:lr;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.26458332;\"\n" + 
            "       xml:space=\"preserve\"><tspan\n" + 
            "         style=\"font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;font-size:4.93888889px;font-family:monospace;-inkscape-font-specification:'monospace, Normal';font-variant-ligatures:normal;font-variant-caps:normal;font-variant-numeric:normal;font-feature-settings:normal;text-align:start;writing-mode:lr;text-anchor:start;stroke-width:0.26458332;\"\n" + 
            "         y=\"293.79272\"\n" + 
            "         x=\"30.735996\"\n" + 
            "         id=\"tspan3757\">$PUK1</tspan></text>\n" + 
            "  </g>\n" + 
            "</svg>";
    private static final int SVG_WIDTH = 856; // width of SVG with 10^2 pixels per mm^2
    private static final int SVG_HEIGHT = 540;

    private static final String[] PINCODES = new String[] { "1234" };
    private static final String[] PUKCODES = new String[] { "8877665544332211" };
    private static final String TEST_USERNAME = "SVGImageManipulatorUnitTest_user";
    private static final String TEST_USERDN = "CN=SVGImageManipulatorUnitTest";
    private static final int TEST_CAID = 0; // not used
    private static final String TEST_SAN = null; // not used

    @Test
    public void printableFromSvgTemplate() throws IOException, PrinterException {
        log.trace(">generateSvgFromTemplate");
        final SVGImageManipulator svgImgMan = new SVGImageManipulator(new StringReader(TEST_SVG), 0);
        final EndEntityInformation eei = new EndEntityInformation(TEST_USERNAME, TEST_USERDN, TEST_CAID, TEST_SAN, null, EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, new ExtendedInformation());
        final Printable result = svgImgMan.print(eei, PINCODES, PUKCODES);
        assertNotNull("null was returned from print method.", result);
        // Now dump the image, so we can check it (needs to be done manually, because the output may vary slightly between systems)
        final BufferedImage img = new BufferedImage(SVG_WIDTH, SVG_HEIGHT, BufferedImage.TYPE_BYTE_GRAY);
        final Graphics graphics = img.createGraphics();
        final PageFormat pageFormat = new PageFormat();
        final Paper paper = pageFormat.getPaper();
        paper.setImageableArea(0, 0, 3.370*72, 2.125*72);
        paper.setSize(3.370*72, 2.125*72);
        pageFormat.setPaper(paper);
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, SVG_WIDTH, SVG_HEIGHT);
        assertEquals("Simulated printing failed", Printable.PAGE_EXISTS, result.print(graphics, pageFormat, 0));
        final byte[] rawImage = (byte[]) img.getRaster().getDataElements(0, 0, SVG_WIDTH, SVG_HEIGHT, null);
        log.trace("Resulting raw image is:\n" + Base64.encodeBase64String(rawImage));
        log.trace("After base64 decoding, the output can be opened as \"raw image data\" of size 856 x 540 in \"Gray 8\" format, for example with GIMP.");
        log.trace("<generateSvgFromTemplate");
    }

}
