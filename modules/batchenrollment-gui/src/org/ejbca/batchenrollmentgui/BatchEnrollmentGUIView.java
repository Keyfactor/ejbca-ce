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
package org.ejbca.batchenrollmentgui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetAdapter;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TooManyListenersException;

import javax.swing.DefaultCellEditor;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.Timer;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EndEntityProfileNotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.jdesktop.application.Action;
import org.jdesktop.application.Application;
import org.jdesktop.application.FrameView;
import org.jdesktop.application.ResourceMap;
import org.jdesktop.application.SingleFrameApplication;
import org.jdesktop.application.Task;
import org.jdesktop.application.TaskMonitor;

/**
 * The application's main frame.
 * 
 * @version $Id$
 */
public class BatchEnrollmentGUIView extends FrameView {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(BatchEnrollmentGUIView.class);

    private JFileChooser openFileChooser;

    private List<Request> requests = new ArrayList<Request>();

    private static final String[] COLUMN_NAMES = new String[] {
        "Status", "Request file", "Request signed by", "Requested DN", 
        "End entity", "Output file"
    };

    private Collection<Certificate> trustedCerts;

    private List<UserDataVOWS> endEntities = new ArrayList<UserDataVOWS>();

    private JComboBox<UserDataVOWS> endEntitiesComboBox = new JComboBox<>();

    private EjbcaWS ejbcaWS;

    public BatchEnrollmentGUIView(SingleFrameApplication app) {
        super(app);

        initSettings();

        initWS();

        initComponents();

        jTable1.setModel(new AbstractTableModel() {

            private static final long serialVersionUID = -2682163886531760122L;

            public int getRowCount() {
                return requests.size();
            }

            public int getColumnCount() {
                return COLUMN_NAMES.length;
            }

            @Override
            public String getColumnName(final int column) {
                return COLUMN_NAMES[column];
            }

            public Object getValueAt(final int rowIndex, int columnIndex) {
                Object value;
                final Request request = requests.get(rowIndex);
                switch (columnIndex) {
                    case 0:
                        value = request.isDone() ? "DONE" : "";
                        break;
                    case 1:
                        value = request.getInFile();
                        break;
                    case 2:
                        value = request.getSignerChain();
                        break;
                    case 3:
                        value = request.getRequestedDN();
                        break;
                    case 4:
                        value = request.getEndEntity();
                        break;
                    case 5:
                        value = request.getOutFile();
                        break;
                    default:
                        value = "";
                }
                return value;
            }

            @Override
            public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
                final Request request = requests.get(rowIndex);
                switch (columnIndex) {
                    case 4:
                        if (aValue instanceof UserDataVOWS) {
                            final UserDataVOWS endEntity = (UserDataVOWS) aValue;
                            request.setEndEntity(endEntity);
                        }
                        break;
                    case 5:
                        if (aValue instanceof String) {
                            requests.get(rowIndex).setOutFile(new File((String) aValue));
                        } else if (aValue instanceof File) {
                            requests.get(rowIndex).setOutFile((File) aValue);
                        }
                }
                fireTableRowsUpdated(rowIndex, rowIndex);
            }

            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return (columnIndex == 2
                        && requests.get(rowIndex).getSignerChain() != null)
                        || (!requests.get(rowIndex).isDone()
                        && (columnIndex == 4 || columnIndex == 5));
            }

        });

        endEntitiesComboBox.setModel(new DefaultComboBoxModel<UserDataVOWS>(endEntities.toArray(new UserDataVOWS[endEntities.size()])));

        endEntitiesComboBox.setRenderer(new DefaultListCellRenderer() {

            private static final long serialVersionUID = 8940720890189526681L;

            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                final Component component =
                        super.getListCellRendererComponent(list, value, index,
                            isSelected, cellHasFocus);
                if (value instanceof UserDataVOWS) {
                    if (component instanceof JTextField) {
                        ((JTextField) component).setText(
                                ((UserDataVOWS) value).getUsername());
                    } else if (component instanceof JLabel) {
                        ((JLabel) component).setText(
                                ((UserDataVOWS) value).getUsername());
                    }
                }
                return component;
            }

        });

        jTable1.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {

            private static final long serialVersionUID = 86357417737074234L;

            private JPanel viewPanel = new JPanel(new BorderLayout());

            private JButton viewButton = new JButton("...");

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {

                if (column == 2 && value != null) {
                    @SuppressWarnings("unchecked")
                    final List<X509Certificate> chain = (List<X509Certificate>) value;
                    value = chain.iterator().next().getSubjectDN().getName();
                    super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                    viewPanel = new JPanel(new BorderLayout());
                    viewPanel.add(this, BorderLayout.CENTER);
                    viewPanel.add(viewButton, BorderLayout.EAST);
                    return viewPanel;
                } else {
                    super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                    return this;
                }
            }

        });

        jTable1.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {

            private static final long serialVersionUID = -2076423436650116932L;

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                if (value instanceof UserDataVOWS) {
                    value = ((UserDataVOWS) value).getUsername();
                }
                return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            }

        });

        jTable1.getColumnModel().getColumn(4).setCellEditor(
                new DefaultCellEditor(endEntitiesComboBox));

        final BrowseCellEditor browseCellEditor =
                new BrowseCellEditor(new JTextField(),
                JFileChooser.SAVE_DIALOG);
        browseCellEditor.setClickCountToStart(1);
        jTable1.getColumnModel().getColumn(5).setCellEditor(
                browseCellEditor);

        final JTextField certTextField = new JTextField();
        certTextField.setEditable(false);
        final CertCellEditor certCellEditor =
                new CertCellEditor(certTextField);

        jTable1.getColumnModel().getColumn(2).setCellEditor(
                certCellEditor);
        certCellEditor.setClickCountToStart(1);
//
//        final ViewCertCellEditor certCellEditor =
//                new ViewCertCellEditor(new JLabel())
//        certCellEditor.setClickCountToStart(1);
//        jTable1.getColumnModel().getColumn(2).setCellEditor(
//                browseCellEditor);

        jTable1.getModel().addTableModelListener(new TableModelListener() {

            public void tableChanged(TableModelEvent e) {
                jTable1Changed(e);
            }
        });

        jTable1.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            public void valueChanged(final ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    jTable1SelectionChanged(e);
                }
            }
        });

        jTable1.setDragEnabled(false);

        final DropTarget dt = new DropTarget();
        try {
            dt.addDropTargetListener(new DropTargetAdapter() {

                @SuppressWarnings("unchecked")
                public void drop(DropTargetDropEvent dtde) {
                    final Transferable tr = dtde.getTransferable();
                    final DataFlavor[] flavors = tr.getTransferDataFlavors();
                    for (DataFlavor flavor : flavors) {
                        if (DataFlavor.javaFileListFlavor.equals(flavor)) {
                            try {
                                dtde.acceptDrop(DnDConstants.ACTION_COPY);
                                for (File file : (List<File>)
                                        tr.getTransferData(
                                            DataFlavor.javaFileListFlavor)) {
                                    addRequest(file);
                                }
                                dtde.dropComplete(true);
                            } catch (UnsupportedFlavorException ex) {
                                JOptionPane.showMessageDialog(getFrame(),
                                    "Adding files failed:\n" + ex.getMessage(),
                                    "Add files", JOptionPane.ERROR_MESSAGE);
                            } catch (IOException ex) {
                                JOptionPane.showMessageDialog(getFrame(),
                                    "Adding files failed:\n" + ex.getMessage(),
                                    "Add files", JOptionPane.ERROR_MESSAGE);
                            }
                        } else if (flavor.getMimeType().contains("text/uri-list")
                                && flavor.getMimeType().contains("java.io.Reader")) {
                            dtde.acceptDrop(DnDConstants.ACTION_COPY);
                            try {
                                BufferedReader in = new BufferedReader(((Reader) tr.getTransferData(flavor)));
                                String uriStr;
                                while ((uriStr = in.readLine()) != null)  {
                                    try {
                                        URL url = new URL(uriStr);
                                        addRequest(url.openStream(), new File(url.toURI()));
                                    } catch (URISyntaxException ex) {
                                        LOG.error("Parsing URL", ex);
                                    } catch (IOException ex) {
                                        LOG.error("Parsing URL", ex);
                                    } catch (CertificateException e) {
                                        LOG.error("Error reading certificate.", e);
                                    }
                                }
                                dtde.dropComplete(true);
                            } catch (UnsupportedFlavorException ex) {
                                throw new RuntimeException(ex);
                            } catch (IOException ex) {
                                throw new RuntimeException(ex);
                            }
                        }
                    }
                }
            });
        } catch (TooManyListenersException ex) {
            throw new RuntimeException(ex);
        }
        jScrollPane1.setDropTarget(dt);

        jTable1Changed(null);

        // status bar initialization - message timeout, idle icon and busy animation, etc
        ResourceMap resourceMap = getResourceMap();
        int messageTimeout = resourceMap.getInteger("StatusBar.messageTimeout");
        messageTimer = new Timer(messageTimeout, new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                statusMessageLabel.setText("");
            }
        });
        messageTimer.setRepeats(false);
        int busyAnimationRate = resourceMap.getInteger("StatusBar.busyAnimationRate");
        for (int i = 0; i < busyIcons.length; i++) {
            busyIcons[i] = resourceMap.getIcon("StatusBar.busyIcons[" + i + "]");
        }
        busyIconTimer = new Timer(busyAnimationRate, new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                busyIconIndex = (busyIconIndex + 1) % busyIcons.length;
                statusAnimationLabel.setIcon(busyIcons[busyIconIndex]);
            }
        });
        idleIcon = resourceMap.getIcon("StatusBar.idleIcon");
        statusAnimationLabel.setIcon(idleIcon);
        progressBar.setVisible(false);

        // connecting action tasks to status bar via TaskMonitor
        TaskMonitor taskMonitor = new TaskMonitor(getApplication().getContext());
        taskMonitor.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                String propertyName = evt.getPropertyName();
                if ("started".equals(propertyName)) {
                    if (!busyIconTimer.isRunning()) {
                        statusAnimationLabel.setIcon(busyIcons[0]);
                        busyIconIndex = 0;
                        busyIconTimer.start();
                    }
                    progressBar.setVisible(true);
                    progressBar.setIndeterminate(true);
                } else if ("done".equals(propertyName)) {
                    busyIconTimer.stop();
                    statusAnimationLabel.setIcon(idleIcon);
                    progressBar.setVisible(false);
                    progressBar.setValue(0);
                } else if ("message".equals(propertyName)) {
                    String text = (String)(evt.getNewValue());
                    statusMessageLabel.setText((text == null) ? "" : text);
                    messageTimer.restart();
                } else if ("progress".equals(propertyName)) {
                    int value = (Integer)(evt.getNewValue());
                    progressBar.setVisible(true);
                    progressBar.setIndeterminate(false);
                    progressBar.setValue(value);
                }
            }
        });

        getContext().getTaskService().execute(refreshEndEntities());
    }

    @Action
    public void showAboutBox() {
        if (aboutBox == null) {
            JFrame mainFrame = BatchEnrollmentGUIApp.getApplication().getMainFrame();
            aboutBox = new BatchEnrollmentGUIAboutBox(mainFrame);
            aboutBox.setLocationRelativeTo(mainFrame);
        }
        BatchEnrollmentGUIApp.getApplication().show(aboutBox);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        mainPanel = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        addButton = new javax.swing.JButton();
        removeButton = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        enrollButton = new javax.swing.JButton();
        clearDoneButton = new javax.swing.JButton();
        menuBar = new javax.swing.JMenuBar();
        javax.swing.JMenu fileMenu = new javax.swing.JMenu();
        javax.swing.JMenuItem exitMenuItem = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();
        settingsMenuItem = new javax.swing.JMenuItem();
        jMenu1 = new javax.swing.JMenu();
        refreshEndEntities = new javax.swing.JMenuItem();
        javax.swing.JMenu helpMenu = new javax.swing.JMenu();
        javax.swing.JMenuItem aboutMenuItem = new javax.swing.JMenuItem();
        statusPanel = new javax.swing.JPanel();
        javax.swing.JSeparator statusPanelSeparator = new javax.swing.JSeparator();
        statusMessageLabel = new javax.swing.JLabel();
        statusAnimationLabel = new javax.swing.JLabel();
        progressBar = new javax.swing.JProgressBar();
        passwordPanel = new javax.swing.JPanel();
        passwordPanelLabel = new javax.swing.JLabel();
        passwordPanelField = new javax.swing.JPasswordField();

        mainPanel.setName("mainPanel"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null}
            },
            new String [] {
                "", "Request file", "Request signed by", "Requested DN", "End enitity", "Output file", "Result"
            }
        ) {
            private static final long serialVersionUID = -1739079282180901839L;
            boolean[] canEdit = new boolean [] {
                false, false, false, false, true, true, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTable1.setDropMode(javax.swing.DropMode.ON_OR_INSERT_ROWS);
        jTable1.setName("jTable1"); // NOI18N
        jScrollPane1.setViewportView(jTable1);

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.ejbca.batchenrollmentgui.BatchEnrollmentGUIApp.class).getContext().getResourceMap(BatchEnrollmentGUIView.class);
        addButton.setText(resourceMap.getString("addButton.text")); // NOI18N
        addButton.setName("addButton"); // NOI18N
        addButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addButtonActionPerformed(evt);
            }
        });

        removeButton.setText(resourceMap.getString("removeButton.text")); // NOI18N
        removeButton.setEnabled(false);
        removeButton.setName("removeButton"); // NOI18N
        removeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeButtonActionPerformed(evt);
            }
        });

        jLabel1.setText(resourceMap.getString("jLabel1.text")); // NOI18N
        jLabel1.setName("jLabel1"); // NOI18N

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.ejbca.batchenrollmentgui.BatchEnrollmentGUIApp.class).getContext().getActionMap(BatchEnrollmentGUIView.class, this);
        enrollButton.setAction(actionMap.get("enroll")); // NOI18N
        enrollButton.setText(resourceMap.getString("enrollButton.text")); // NOI18N
        enrollButton.setName("enrollButton"); // NOI18N

        clearDoneButton.setText(resourceMap.getString("clearDoneButton.text")); // NOI18N
        clearDoneButton.setEnabled(false);
        clearDoneButton.setName("clearDoneButton"); // NOI18N
        clearDoneButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                clearDoneButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                        .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 909, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(addButton)
                            .addComponent(removeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 81, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(clearDoneButton)))
                    .addComponent(enrollButton, javax.swing.GroupLayout.PREFERRED_SIZE, 83, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        mainPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {addButton, clearDoneButton, enrollButton, removeButton});

        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(12, 12, 12)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(addButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(removeButton)
                        .addGap(18, 18, 18)
                        .addComponent(clearDoneButton))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 329, Short.MAX_VALUE))
                .addGap(18, 18, 18)
                .addComponent(enrollButton)
                .addContainerGap())
        );

        menuBar.setName("menuBar"); // NOI18N

        fileMenu.setMnemonic('F');
        fileMenu.setText(resourceMap.getString("fileMenu.text")); // NOI18N
        fileMenu.setName("fileMenu"); // NOI18N

        exitMenuItem.setAction(actionMap.get("quit")); // NOI18N
        exitMenuItem.setName("exitMenuItem"); // NOI18N
        fileMenu.add(exitMenuItem);

        menuBar.add(fileMenu);

        jMenu2.setMnemonic('E');
        jMenu2.setText(resourceMap.getString("jMenu2.text")); // NOI18N
        jMenu2.setName("jMenu2"); // NOI18N

        settingsMenuItem.setText(resourceMap.getString("settingsMenuItem.text")); // NOI18N
        settingsMenuItem.setName("settingsMenuItem"); // NOI18N
        settingsMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                settingsMenuItemActionPerformed(evt);
            }
        });
        jMenu2.add(settingsMenuItem);

        menuBar.add(jMenu2);

        jMenu1.setAction(actionMap.get("refreshEndEntities")); // NOI18N
        jMenu1.setText(resourceMap.getString("jMenu1.text")); // NOI18N
        jMenu1.setName("jMenu1"); // NOI18N

        refreshEndEntities.setAction(actionMap.get("refreshEndEntities")); // NOI18N
        refreshEndEntities.setText(resourceMap.getString("refreshEndEntities.text")); // NOI18N
        refreshEndEntities.setName("refreshEndEntities"); // NOI18N
        jMenu1.add(refreshEndEntities);

        menuBar.add(jMenu1);

        helpMenu.setMnemonic('H');
        helpMenu.setText(resourceMap.getString("helpMenu.text")); // NOI18N
        helpMenu.setName("helpMenu"); // NOI18N

        aboutMenuItem.setAction(actionMap.get("showAboutBox")); // NOI18N
        aboutMenuItem.setName("aboutMenuItem"); // NOI18N
        helpMenu.add(aboutMenuItem);

        menuBar.add(helpMenu);

        statusPanel.setName("statusPanel"); // NOI18N

        statusPanelSeparator.setName("statusPanelSeparator"); // NOI18N

        statusMessageLabel.setName("statusMessageLabel"); // NOI18N

        statusAnimationLabel.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        statusAnimationLabel.setName("statusAnimationLabel"); // NOI18N

        progressBar.setName("progressBar"); // NOI18N

        javax.swing.GroupLayout statusPanelLayout = new javax.swing.GroupLayout(statusPanel);
        statusPanel.setLayout(statusPanelLayout);
        statusPanelLayout.setHorizontalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(statusPanelSeparator, javax.swing.GroupLayout.DEFAULT_SIZE, 1037, Short.MAX_VALUE)
            .addGroup(statusPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(statusMessageLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 851, Short.MAX_VALUE)
                .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(statusAnimationLabel)
                .addContainerGap())
        );
        statusPanelLayout.setVerticalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusPanelLayout.createSequentialGroup()
                .addComponent(statusPanelSeparator, javax.swing.GroupLayout.PREFERRED_SIZE, 2, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(statusMessageLabel)
                    .addComponent(statusAnimationLabel)
                    .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(3, 3, 3))
        );

        passwordPanel.setName("passwordPanel"); // NOI18N

        passwordPanelLabel.setText(resourceMap.getString("passwordPanelLabel.text")); // NOI18N
        passwordPanelLabel.setName("passwordPanelLabel"); // NOI18N

        passwordPanelField.setText(resourceMap.getString("passwordPanelField.text")); // NOI18N
        passwordPanelField.setName("passwordPanelField"); // NOI18N

        javax.swing.GroupLayout passwordPanelLayout = new javax.swing.GroupLayout(passwordPanel);
        passwordPanel.setLayout(passwordPanelLayout);
        passwordPanelLayout.setHorizontalGroup(
            passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passwordPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(passwordPanelField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE)
                    .addComponent(passwordPanelLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE))
                .addContainerGap())
        );
        passwordPanelLayout.setVerticalGroup(
            passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passwordPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passwordPanelLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(passwordPanelField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        setComponent(mainPanel);
        setMenuBar(menuBar);
        setStatusBar(statusPanel);
    }// </editor-fold>//GEN-END:initComponents

    private void addButtonActionPerformed(java.awt.event.ActionEvent evt) {//NOPMD//GEN-FIRST:event_addButtonActionPerformed
        final JFileChooser fc = getOpenFileChooser();
        final int result = fc.showOpenDialog(getFrame());
        if (result == JFileChooser.APPROVE_OPTION) {
            for (File file : fc.getSelectedFiles()) {
                addRequest(file);
            }
        }
    }//GEN-LAST:event_addButtonActionPerformed

    private void clearDoneButtonActionPerformed(java.awt.event.ActionEvent evt) {//NOPMD//GEN-FIRST:event_clearDoneButtonActionPerformed
        for (int i = requests.size() - 1; i >= 0; i--) {
            if (requests.get(i).isDone()) {
                requests.remove(i);
            }
        }
        jTable1.revalidate();
    }//GEN-LAST:event_clearDoneButtonActionPerformed

    private void removeButtonActionPerformed(java.awt.event.ActionEvent evt) {//NOPMD//GEN-FIRST:event_removeButtonActionPerformed
        int[] selected = jTable1.getSelectedRows();
        Arrays.sort(selected);
        for (int i = selected.length - 1; i >= 0; i--) {
            requests.remove(selected[i]);
        }
        jTable1.revalidate();
//        jTable1.valueChanged(null);
    }//GEN-LAST:event_removeButtonActionPerformed

    private void settingsMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//NOPMD//GEN-FIRST:event_settingsMenuItemActionPerformed
        final SettingsDialog dlg = new SettingsDialog(getFrame(), true,
                getApp().getSettings());
        dlg.setVisible(true);
        final Settings newSettings = dlg.getSettings();
        if (newSettings != null) {
            LOG.debug("newSettings: " + newSettings);
            try {
                getApp().saveSettings(newSettings);
                trustedCerts = null;
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(getFrame(), "Unable to save settings: "
                        + ex.getMessage());
            }
        }
    }//GEN-LAST:event_settingsMenuItemActionPerformed

    private void jTable1Changed(TableModelEvent e) { // NOPMD
        System.out.println("tableChanged");
        boolean enable = false;
        for (Request request : requests) {
            if (!request.isDone()) {
                enable = true;
                if (request.getOutFile() == null
                        || request.getEndEntity() == null
                        || request.getEndEntity() == null) {
                    enable = false;
                    break;
                }
            }
        }
        enrollButton.setEnabled(enable);
    }

    private Collection<Certificate> getTrustedCerts() {
        if (trustedCerts == null) {
            String truststore = getApp().getSettings().getTruststorePath();
            if (truststore == null || !new File(truststore).exists()) {
                LOG.error("Non-existing truststore: " + truststore);
                JOptionPane.showMessageDialog(getFrame(),
                        "Please configure the truststore first");
            } else {
                try {
                    trustedCerts = new HashSet<Certificate>();
                    trustedCerts.addAll(CertTools.getCertsFromPEM(getApp().getSettings().getTruststorePath(), Certificate.class));
                } catch (IOException ex) {
                    LOG.error("Load trusted certificates failed", ex);
                } catch (CertificateException ex) {
                    LOG.error("Load trusted certificates failed", ex);
                }
            }
        }
        return trustedCerts;
    }

    private BatchEnrollmentGUIApp getApp() {
        final BatchEnrollmentGUIApp guiApp;
        final Application app = getApplication();
        if (app instanceof BatchEnrollmentGUIApp) {
            guiApp = (BatchEnrollmentGUIApp) app;
        } else {
            throw new RuntimeException("Wrong type of application");
        }
        return guiApp;
    }

    private JFileChooser getOpenFileChooser() {
        if (openFileChooser == null) {
            openFileChooser = new JFileChooser();
            openFileChooser.setMultiSelectionEnabled(true);
            openFileChooser.setDialogType(JFileChooser.OPEN_DIALOG);
        }
        return openFileChooser;
    }

    private void addRequest(final File file) {
        try {
            addRequest(new FileInputStream(file), file);
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(getFrame(),
                    "File not found:\n" + ex.getMessage(), "Add request",
                    JOptionPane.ERROR_MESSAGE);
        } catch(CertificateException e) {
            JOptionPane.showMessageDialog(getFrame(),
                    "Error reading certificate.\n" + e.getMessage(), "Add request",
                    JOptionPane.ERROR_MESSAGE);
            LOG.error("Error reading certificate.", e);
        }
    }

    private void addRequest(final InputStream inStream, final File inFile) throws CertificateException {

        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        BufferedInputStream in = null;
        try {
            in = new BufferedInputStream(inStream);
            int b;
            while ((b = in.read()) != -1) {
                bout.write(b);
            }
            final byte[] bytes = bout.toByteArray();

            CMSSignedData signedData = null;
            try {
                signedData = new CMSSignedData(bytes);
            } catch (Exception ex) {
                LOG.debug("Not parsed as CMS: " + ex.getMessage());
            }
            
            final byte[] requestBytes;
            final Request request = new Request();

            if (signedData == null) {
                requestBytes = bytes;
            } else {
                final CMSValidationResult result
                        = validateCMS(signedData, getTrustedCerts());
                requestBytes = result.getContent();
                request.setSignerChain(result.getSignerChain());
            }

            // Parse PKCS10 and fill in requested DN
            PKCS10CertificationRequest pkcs10 = getPkcs10Request(requestBytes);
            request.setRequestedDN(pkcs10.getSubject().toString());

            request.setInFile(inFile);
            request.setOutFile(new File(inFile.getParentFile(), 
                    suggestOutFile(inFile.getName())));
            request.setRequestBytes(requestBytes);

            // Try to match beginning of filename with a user
            for (UserDataVOWS user : endEntities) {
                if (inFile.getName().toLowerCase(Locale.ENGLISH).contains(
                        user.getUsername().toLowerCase(Locale.ENGLISH))) {
                    request.setEndEntity(findEndEntity(user.getUsername()));
                    break;
                }
            }

            requests.add(request);
            jTable1.revalidate();
            jTable1Changed(new TableModelEvent(jTable1.getModel(),
                    requests.size()-1, requests.size()-1,
                    TableModelEvent.ALL_COLUMNS, TableModelEvent.INSERT));

        } catch (IOException ex) {
            JOptionPane.showMessageDialog(getFrame(),
                    "Problem reading file:\n" + ex.getMessage(), "Add request",
                    JOptionPane.ERROR_MESSAGE);
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(getFrame(),
                    "Problem parsing request:\n" + ex.getMessage(), "Add request",
                    JOptionPane.ERROR_MESSAGE);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Error closing input file", ex);
                }
            }
        }
    }

    private static String suggestOutFile(final String inFile) {
        String title;
        if (inFile.contains(".")) {
            title = inFile.substring(0, inFile.lastIndexOf("."));
        } else {
            title = inFile;
        }
        return title + ".pem";
    }

    @SuppressWarnings("unchecked")
    private static CMSValidationResult validateCMS(final CMSSignedData signedData,
            final Collection<Certificate> trustedCerts) {

        final CMSValidationResult result = new CMSValidationResult();

        try {
            final ContentInfo ci = signedData.toASN1Structure();
            if (LOG.isDebugEnabled()) {
                LOG.debug("ci.content: " + ci.getContent() + "\n"
                    + "signedContent: " + signedData.getSignedContent());
            }

            final Object content = signedData.getSignedContent().getContent();

            if (content instanceof byte[]) {
                result.setContent((byte[]) content);
            }

            Store<X509CertificateHolder> certs = signedData.getCertificates();
            SignerInformationStore  signers = signedData.getSignerInfos();
            for (Object o : signers.getSigners()) {
                if (o instanceof SignerInformation) {
                    SignerInformation si = (SignerInformation) o;

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("*** SIGNATURE: " + "\n" + si.getSID());
                    }
                    
                    final Collection<X509CertificateHolder> signerCerts = (Collection<X509CertificateHolder>)certs.getMatches(si.getSID());

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("signerCerts: " + signerCerts);
                    }
                    JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
                    for (X509CertificateHolder signerCert : signerCerts) {
                        final X509Certificate signerX509Cert = jcaX509CertificateConverter.getCertificate(signerCert);
                        
                        // Verify the signature
                        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                        JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(
                                calculatorProviderBuilder.build()).setProvider(BouncyCastleProvider.PROVIDER_NAME);
                        boolean consistent = si.verify(jcaSignerInfoVerifierBuilder.build(signerX509Cert.getPublicKey()));
                        if (consistent) {

                            if (LOG.isDebugEnabled()) {
                                LOG.debug((consistent ? "Consistent" : "Inconsistent") + " signature from " + signerX509Cert.getSubjectDN()
                                        + " issued by " + signerX509Cert.getIssuerDN());
                            }

                            result.setValidSignature(consistent);

                            try {
                                final List<X509Certificate> signerChain = validateChain(signerX509Cert, certs, trustedCerts);

                                result.setValidChain(true);
                                result.setSignerChain(signerChain);

                                JOptionPane.showMessageDialog(null, "Found valid signature from \"" + signerX509Cert.getSubjectDN() + "\"",
                                        "Signature check", JOptionPane.INFORMATION_MESSAGE);

                            } catch (CertPathBuilderException ex) {
                                result.setError(ex.getMessage());
                                JOptionPane.showMessageDialog(null, "Error: Certificate path:\n" + ex.getMessage(), "Signature check",
                                        JOptionPane.ERROR_MESSAGE);
                            } catch (CertPathValidatorException ex) {
                                result.setError(ex.getMessage());
                                JOptionPane.showMessageDialog(null, "Error: Certificate validation:\n" + ex.getMessage(), "Signature check",
                                        JOptionPane.ERROR_MESSAGE);
                            } catch (InvalidAlgorithmParameterException ex) {
                                result.setError(ex.getMessage());
                                JOptionPane.showMessageDialog(null, ex.getMessage(), "Signature check", JOptionPane.ERROR_MESSAGE);
                            } catch (NoSuchAlgorithmException ex) {
                                result.setError(ex.getMessage());
                                JOptionPane.showMessageDialog(null, ex.getMessage(), "Signature check", JOptionPane.ERROR_MESSAGE);
                            } catch (GeneralSecurityException e) {
                                //Crappy catch-all, but not much to do due to underlying BC-code
                                result.setError(e.getMessage());
                                JOptionPane.showMessageDialog(null, e.getMessage(), "Error: Certificate validation:\n", JOptionPane.ERROR_MESSAGE);
                            }
                        } else {
                            result.setError("Inconsistent signature!");
                            JOptionPane.showMessageDialog(null, "Error: Inconsisten signature!", "Signature check", JOptionPane.ERROR_MESSAGE);
                        }
                    }
       
                }
            }

        } catch (CMSException ex) {
            result.setError(ex.getMessage());
            LOG.error("Parsing and validating CMS", ex);
        } catch (OperatorCreationException ex) {
            result.setError(ex.getMessage());
            LOG.error("Parsing and validating CMS", ex);
        } catch (CertificateException ex) {
            result.setError(ex.getMessage());
            LOG.error("Parsing and validating CMS", ex);
        }
        return result;
    }

    private static List<X509Certificate> validateChain(X509Certificate signerCert, Store<X509CertificateHolder> certs, Collection<Certificate> trustedCerts) throws GeneralSecurityException {

        final Set<TrustAnchor> anchors
                = new HashSet<TrustAnchor>();
        for (Certificate cert : trustedCerts) {
        	if (cert instanceof X509Certificate) {
                anchors.add(new TrustAnchor((X509Certificate)cert, null));
			}
        }

        final CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
        X509CertSelector targetConstraints = new X509CertSelector();
        targetConstraints.setCertificate(signerCert);
        PKIXBuilderParameters cpbParams =
            new PKIXBuilderParameters(anchors, targetConstraints);
        JcaCertStoreBuilder jcaCertStoreBuilder = new JcaCertStoreBuilder();
        jcaCertStoreBuilder.addCertificates(certs);
        
        cpbParams.addCertStore(jcaCertStoreBuilder.build());
        cpbParams.setRevocationEnabled(false);

        // Build path
        PKIXCertPathBuilderResult cpbResult =
            (PKIXCertPathBuilderResult) cpb.build(cpbParams);
        CertPath certPath = cpbResult.getCertPath();

        // Validate path
        final CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        final PKIXParameters params = new PKIXParameters(anchors);
        params.setSigProvider(BouncyCastleProvider.PROVIDER_NAME);
        params.setRevocationEnabled(false);

        PKIXCertPathValidatorResult result =
            (PKIXCertPathValidatorResult) cpv.validate(certPath, params);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found trust anchor: " + result.getTrustAnchor());
        }

        List<X509Certificate> signerChain = new ArrayList<X509Certificate>();

        for (Certificate cert : certPath.getCertificates()) {
            signerChain.add((X509Certificate) cert);
        }
        if (signerChain.size() > 0) {
            signerChain.add(result.getTrustAnchor().getTrustedCert());
        }

        return signerChain;
    }

    @Action
    public Task<Object, Void> refreshEndEntities() {
        return new RefreshEndEntitiesTask(getApplication());
    }

    private void initWS() {
    	CryptoProviderTools.installBCProvider();

        final ConnectDialog dlg = new ConnectDialog(null, true);
        dlg.setVisible(true);
        ejbcaWS = dlg.getEjbcaWS();
        
        if (ejbcaWS == null) {
            getApplication().exit();
        }
    }

    private PKCS10CertificationRequest getPkcs10Request(byte[] requestBytes)
            throws IOException, IllegalArgumentException {
        return new PKCS10CertificationRequest(
                RequestMessageUtils.getRequestBytes(requestBytes));
    }

    private void initSettings() {
        try {
            getApp().loadSettings();
        } catch (IOException ex) {
            LOG.error("Unable to load settings", ex);
            JOptionPane.showMessageDialog(null, "Unable to load settings: "
                    + ex.getMessage());
            getApp().setSettings(new Settings());
        }
    }

    private class RefreshEndEntitiesTask extends org.jdesktop.application.Task<Object, Void> {
        RefreshEndEntitiesTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to RefreshEndEntitiesTask fields, here.
            super(app);
        }
        @Override protected Object doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            Object result;
            final List<UserDataVOWS> users = new ArrayList<UserDataVOWS>();

            try {
                List<NameAndId> cas = ejbcaWS.getAvailableCAs();
                for (NameAndId ca : cas) {
                    UserMatch um = new UserMatch();
                    um.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
                    um.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_CA);
                    um.setMatchvalue(ca.getName());
                    users.addAll(ejbcaWS.findUser(um));
                }
                result = users;
            } catch (AuthorizationDeniedException_Exception ex) {
                result = ex;
            } catch (IllegalQueryException_Exception ex) {
                result = ex;
            } catch (EndEntityProfileNotFoundException_Exception ex) {
                result = ex;
            } catch (EjbcaException_Exception ex) {
                result = ex;
            }
            return result;  // return your result
        }
        @Override protected void succeeded(Object result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result instanceof ArrayList) {
                @SuppressWarnings("unchecked")
                final ArrayList<UserDataVOWS> newUsers = (ArrayList<UserDataVOWS>) result;
                endEntities = newUsers;

                if (LOG.isDebugEnabled()) {
                    LOG.debug("list: " + endEntities);
                }
                endEntitiesComboBox.setModel(
                        new DefaultComboBoxModel<UserDataVOWS>(endEntities.toArray(new UserDataVOWS[endEntities.size()])));
                endEntitiesComboBox.revalidate();
            } else if (result instanceof Exception) {
                final Exception ex = (Exception) result;
                JOptionPane.showMessageDialog(getFrame(), ex.getMessage());
            }
        }
    }

    @Action
    public Task<Object, Void> enroll() {
        return new EnrollTask(getApplication());
    }

    private class EnrollTask extends org.jdesktop.application.Task<Object, Void> {

        private char[] password;

        EnrollTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to EnrollTask fields, here.
            super(app);

            passwordPanelLabel.setText(
                    "Enter password for all end entities:");
            passwordPanelField.setText("");
            passwordPanelField.grabFocus();

            int res = JOptionPane.showConfirmDialog(getFrame(), passwordPanel,
                    "Enroll", JOptionPane.OK_CANCEL_OPTION);


            if (res == JOptionPane.OK_OPTION) {
                password = passwordPanelField.getPassword();
            } else {
                password = null;
            }
        }
        @Override protected Object doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.

            // TODO do checks etcs

            for (Request request : requests) {
                if (!request.isDone()) {
                    PrintWriter out = null;
                    try {
                        out = new PrintWriter(new FileOutputStream(
                                request.getOutFile()));

                        if (request.getEndEntity().getStatus() != 10) {
                            final UserDataVOWS user = request.getEndEntity();
                            user.setPassword(new String(password));
                            user.setStatus(10);
                            ejbcaWS.editUser(user);
                        }

                        final CertificateResponse response =
                                ejbcaWS.pkcs10Request(request.getEndEntity()
                                    .getUsername(),
                                new String(password),
                                new String(request.getRequestBytes()), null,
                                CertificateHelper.RESPONSETYPE_CERTIFICATE);

                        final String base64EncodedData
                                = new String(response.getData());

                        out.println("-----BEGIN CERTIFICATE-----");
                        out.println(base64EncodedData);
                        out.println("-----END CERTIFICATE-----");
                        request.setDone(true);
                    } catch (Exception ex) {
                        final String error = ex.getMessage();
                        LOG.error(error, ex);
                        JOptionPane.showMessageDialog(getFrame(), error,
                                "Enrolling", JOptionPane.ERROR_MESSAGE);
					} finally {
                        if (out != null) {
                            out.close();
                        }
                    }
                }
            }

            int done = 0, failed = 0;
            for (Request request : requests) {
                if (request.isDone()) {
                    done++;
                } else {
                    failed++;
                }
            }
            JOptionPane.showMessageDialog(getFrame(), "Successfull requests: "
                    + done + "\n" + "Failed or unfinished requests: " + failed);

            return null;  // return your result
        }
        @Override protected void succeeded(Object result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            jTable1Changed(null);
            jTable1SelectionChanged(null);
        }
    }

    private UserDataVOWS findEndEntity(final String username) {
        UserDataVOWS endentity = null;
        for (UserDataVOWS user : endEntities) {
            if (user.getUsername().equals(username)) {
                endentity = user;
                break;
            }
        }
        return endentity;
    }

    private void jTable1SelectionChanged(final ListSelectionEvent e) { // NOPMD
        removeButton.setEnabled(!jTable1.getSelectionModel()
                .isSelectionEmpty());

        boolean clearFinished = false;
        for (Request request : requests) {
            if (request.isDone()) {
                clearFinished = true;
                break;
            }
        }
        clearDoneButton.setEnabled(clearFinished);
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addButton;
    private javax.swing.JButton clearDoneButton;
    private javax.swing.JButton enrollButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JMenuBar menuBar;
    private javax.swing.JPanel passwordPanel;
    private javax.swing.JPasswordField passwordPanelField;
    private javax.swing.JLabel passwordPanelLabel;
    private javax.swing.JProgressBar progressBar;
    private javax.swing.JMenuItem refreshEndEntities;
    private javax.swing.JButton removeButton;
    private javax.swing.JMenuItem settingsMenuItem;
    private javax.swing.JLabel statusAnimationLabel;
    private javax.swing.JLabel statusMessageLabel;
    private javax.swing.JPanel statusPanel;
    // End of variables declaration//GEN-END:variables

    private final Timer messageTimer;
    private final Timer busyIconTimer;
    private final Icon idleIcon;
    private final Icon[] busyIcons = new Icon[15];
    private int busyIconIndex = 0;

    private JDialog aboutBox;
}
