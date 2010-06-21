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
 * @version $Id$
 */
class BrowseCellEditor extends DefaultCellEditor implements ActionListener {

    private JButton customEditorButton = new JButton("...");
    private JTable table;
    private int row;
    private int column;
    private JFileChooser chooser = new JFileChooser();

    public BrowseCellEditor(JTextField textField, int dialogType) {
        super(textField);
        chooser.setMultiSelectionEnabled(false);
        chooser.setDialogType(dialogType);
        customEditorButton.addActionListener(this);
    }

    public void actionPerformed(ActionEvent e) {
        stopCellEditing();
        final Object value = table.getValueAt(row, column);
        final File currentFile;
        if (value instanceof File) {
            currentFile = (File) value;
        } else {
            currentFile = new File(value.toString());
        }
        chooser.setSelectedFile(currentFile);
        final int result;
        if (chooser.getDialogType() == JFileChooser.OPEN_DIALOG) {
            result = chooser.showOpenDialog(null);
        } else if (chooser.getDialogType() == JFileChooser.SAVE_DIALOG) {
            result = chooser.showSaveDialog(null);
        } else {
            result = chooser.showDialog(null, "OK");
        }
        if (result == JFileChooser.APPROVE_OPTION) {

            if (chooser.getDialogType() == JFileChooser.SAVE_DIALOG
                    && chooser.getSelectedFile().exists()) {
                final int response = JOptionPane.showConfirmDialog(null,
                    "Overwrite existing file?", "Confirm Overwrite",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
                if (response == JOptionPane.CANCEL_OPTION) {
                    return;
                }
            }
            
            table.setValueAt(chooser.getSelectedFile().getAbsolutePath(),
                    row, column);
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

    public JFileChooser getFileChooser() {
        return chooser;
    }

}
