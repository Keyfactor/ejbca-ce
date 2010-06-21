/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.batchenrollmentgui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;

/**
 * Cell editor with text field and button for browsing to a filename to save as.
 *
 * @author markus
 * @version $Id: BrowseCellEditor.java 1043 2010-06-02 11:21:01Z netmackan $
 */
class CertCellEditor extends DefaultCellEditor implements ActionListener {

    private JButton customEditorButton = new JButton("...");
    private JTable table;
    private int row;
    private int column;

    public CertCellEditor(JTextField textField) {
        super(textField);
        customEditorButton.addActionListener(this);
    }

    public void actionPerformed(ActionEvent e) {
        stopCellEditing();
        final Object value = table.getValueAt(row, column);
        
        if (value instanceof List) {
            final List<X509Certificate> certs = (List) value;
            final ViewCertificateFrame frame = new ViewCertificateFrame(certs);
            frame.setVisible(true);
        }
    }

    @Override
    public Component getTableCellEditorComponent(final JTable table,
            final Object value, final boolean isSelected, final int row,
            final int column) {
        final JPanel panel = new JPanel(new BorderLayout());
        final Component defaultComponent
                = super.getTableCellEditorComponent(table, value, isSelected,
                row, column);
        panel.add(defaultComponent);
        panel.add(customEditorButton, BorderLayout.EAST);
        this.table = table;
        this.row = row;
        this.column = column;
        return panel;
    }

}
