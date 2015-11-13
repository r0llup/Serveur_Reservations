/**
 * Serveur_Reservations
 *
 * Copyright (C) 2012 Sh1fT
 *
 * This file is part of Serveur_Reservations.
 *
 * Serveur_Reservations is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3 of the License,
 * or (at your option) any later version.
 *
 * Serveur_Reservations is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Serveur_Reservations; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

package serveur_reservations;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.awt.Color;
import java.awt.Frame;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.JDialog;
import javax.swing.JLabel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import protocols.ProtocolRMP;
import utils.PropertiesLauncher;

/**
 * Manage a {@link Serveur_Reservations}
 * @author Sh1fT
 */
public class Serveur_Reservations extends JDialog {
    private ProtocolRMP protocolRMP;
    private DemarrerServeur2 demarrerServeur2;
    private PropertiesLauncher propertiesLauncher;
    private SecretKey secretKey;
    private KeyPair keyPair;
    private PublicKey clientPublicKey;

    /**
     * Create a new {@link Serveur_Reservations} instance
     * @param parent
     * @param modal 
     */
    public Serveur_Reservations(Frame parent, boolean modal) {
        super(parent, modal);
        this.initComponents();
        this.setProtocolRMP(new ProtocolRMP(this));
        this.setDemarrerServeur2(null);
        this.setPropertiesLauncher(new PropertiesLauncher(
                System.getProperty("file.separator") + "properties" +
                System.getProperty("file.separator") + "Serveur_Reservations.properties"));
        this.setSecretKey(null);
        this.setKeyPair(null);
        this.setClientPublicKey((PublicKey) null);
    }

    /**
     * Encrypt the client name
     * @param clientName
     * @return 
     */
    public String encryptClientName(String clientName) {
        try {
            Cipher cipher = Cipher.getInstance("Rijndael/CBC/PKCS5Padding", "BC");
            byte[] initVector = new byte[16];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(initVector);
            cipher.init(Cipher.ENCRYPT_MODE, this.getSecretKey(),
                    new IvParameterSpec(initVector));
            return Base64.encode(cipher.doFinal(clientName.getBytes())) +
                "~" + Base64.encode(initVector) + "~";
        } catch (NoSuchAlgorithmException | NoSuchProviderException | 
                NoSuchPaddingException | IllegalBlockSizeException |
                BadPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            this.getProtocolRMP().getBdbam().stop();
            System.exit(1);
        }
        return null;
    }

    /**
     * Decrypt the client name
     * @param clientName
     * @return 
     */
    public String decryptClientName(String clientName) {
        try {
            Cipher cipher = Cipher.getInstance("Rijndael/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, this.getSecretKey(),
                    new IvParameterSpec(Base64.decode(clientName.split("~")[1])));
            return new String(cipher.doFinal(Base64.decode(clientName.split("~")[0])));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | 
                NoSuchPaddingException | IllegalBlockSizeException |Base64DecodingException |
                BadPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
        return null;
    }

    /**
     * Generate a key pair
     */
    public void genKeyPair() {
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
            keygen.initialize(4096, new SecureRandom());
            this.setKeyPair(keygen.generateKeyPair());
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
    }

    /**
     * Verify a signature
     * @param sigActual
     * @param sigExpected
     * @param publicKey
     * @return 
     */
    public Boolean verifySignature(String sigActual, String sigExpected,
            PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("MD5WithRSA");
            sig.initVerify(publicKey);
            sig.update(sigExpected.getBytes());
            return sig.verify(Base64.decode(sigActual));
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                SignatureException | Base64DecodingException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
        return null;
    }

    public ProtocolRMP getProtocolRMP() {
        return protocolRMP;
    }

    public void setProtocolRMP(ProtocolRMP protocolRMP) {
        this.protocolRMP = protocolRMP;
    }

    public DemarrerServeur2 getDemarrerServeur2() {
        return demarrerServeur2;
    }

    public void setDemarrerServeur2(DemarrerServeur2 demarrerServeur2) {
        this.demarrerServeur2 = demarrerServeur2;
    }

    public PropertiesLauncher getPropertiesLauncher() {
        return propertiesLauncher;
    }

    public void setPropertiesLauncher(PropertiesLauncher propertiesLauncher) {
        this.propertiesLauncher = propertiesLauncher;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public PublicKey getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(PublicKey clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public void setClientPublicKey(byte[] publicKeyData) {
        try {
          X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyData);
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          this.setClientPublicKey((RSAPublicKey) keyFactory.generatePublic(publicKeySpec));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        } 
    }

    public JLabel getClientLabel() {
        return this.clientLabel;
    }

    public Properties getProperties() {
        return this.getPropertiesLauncher().getProperties();
    }

    public Integer getServerPort() {
        return Integer.parseInt(this.getProperties().getProperty("serverPort"));
    }

    public String getCreditServerHost() {
        return this.getProperties().getProperty("creditServerHost");
    }

    public Integer getCreditServerPort() {
        return Integer.parseInt(this.getProperties().getProperty("creditServerPort"));
    }

    public String getBanqueServerHost() {
        return this.getProperties().getProperty("banqueServerHost");
    }

    public Integer getBanqueServerPort() {
        return Integer.parseInt(this.getProperties().getProperty("banqueServerPort"));
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        toggleButtonGroup = new javax.swing.ButtonGroup();
        jPanel1 = new javax.swing.JPanel();
        demarrerToggleButton = new javax.swing.JToggleButton();
        arreterToggleButton = new javax.swing.JToggleButton();
        jPanel2 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        etatLabel = new javax.swing.JLabel();
        clientLabel = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        quitterButton = new javax.swing.JButton();

        this.toggleButtonGroup.add(this.demarrerToggleButton);
        this.toggleButtonGroup.add(this.arreterToggleButton);

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Serveur_Reservations");
        setResizable(false);

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Actions", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Verdana", 0, 10), java.awt.Color.darkGray)); // NOI18N

        demarrerToggleButton.setFont(new java.awt.Font("Verdana", 0, 11)); // NOI18N
        demarrerToggleButton.setText("Démarrer");
        demarrerToggleButton.setBorder(javax.swing.BorderFactory.createTitledBorder(""));
        demarrerToggleButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                demarrerToggleButtonActionPerformed(evt);
            }
        });

        arreterToggleButton.setFont(new java.awt.Font("Verdana", 0, 11)); // NOI18N
        arreterToggleButton.setText("Arrêter");
        arreterToggleButton.setBorder(javax.swing.BorderFactory.createTitledBorder(""));
        arreterToggleButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                arreterToggleButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap(99, Short.MAX_VALUE)
                .addComponent(demarrerToggleButton)
                .addGap(18, 18, 18)
                .addComponent(arreterToggleButton)
                .addContainerGap(115, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(arreterToggleButton)
                    .addComponent(demarrerToggleButton))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Informations", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Verdana", 0, 10), java.awt.Color.darkGray)); // NOI18N

        jLabel1.setFont(new java.awt.Font("Verdana", 0, 11)); // NOI18N
        jLabel1.setText("Client connecté :");

        jLabel2.setFont(new java.awt.Font("Verdana", 0, 11)); // NOI18N
        jLabel2.setText("État du serveur :");

        etatLabel.setFont(new java.awt.Font("Verdana", 2, 11)); // NOI18N
        etatLabel.setText("inconnu");

        clientLabel.setFont(new java.awt.Font("Verdana", 2, 11)); // NOI18N
        clientLabel.setText("aucun");

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addGap(18, 18, 18)
                        .addComponent(etatLabel))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addGap(18, 18, 18)
                        .addComponent(clientLabel)))
                .addContainerGap(225, Short.MAX_VALUE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(etatLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(clientLabel)))
        );

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder(""));

        quitterButton.setFont(new java.awt.Font("Verdana", 0, 11)); // NOI18N
        quitterButton.setText("Quitter");
        quitterButton.setBorder(javax.swing.BorderFactory.createTitledBorder(""));
        quitterButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                quitterButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(156, 156, 156)
                .addComponent(quitterButton)
                .addContainerGap(175, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(quitterButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jPanel3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(6, 6, 6)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(1, 1, 1)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void demarrerToggleButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_demarrerToggleButtonActionPerformed
        if (this.getDemarrerServeur2() == null) {
            this.setDemarrerServeur2(new DemarrerServeur2(this));
            this.getDemarrerServeur2().start();
            this.genKeyPair();
            this.etatLabel.setForeground(Color.green);
            this.etatLabel.setText("démarré");
        }
    }//GEN-LAST:event_demarrerToggleButtonActionPerformed

    private void arreterToggleButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_arreterToggleButtonActionPerformed
        if (this.getDemarrerServeur2() != null) {
            this.getDemarrerServeur2().interrupt();
            this.setDemarrerServeur2(null);
            this.etatLabel.setForeground(Color.red);
            this.etatLabel.setText("arrêté");
            this.clientLabel.setText("");
        }
    }//GEN-LAST:event_arreterToggleButtonActionPerformed

    private void quitterButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_quitterButtonActionPerformed
        if (this.getDemarrerServeur2() != null)
            this.getDemarrerServeur2().interrupt();
        System.exit(0);
    }//GEN-LAST:event_quitterButtonActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Windows".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
        //</editor-fold>

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                Security.addProvider(new BouncyCastleProvider());
                Serveur_Reservations dialog = new Serveur_Reservations(new javax.swing.JFrame(), true);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JToggleButton arreterToggleButton;
    private javax.swing.JLabel clientLabel;
    private javax.swing.JToggleButton demarrerToggleButton;
    private javax.swing.JLabel etatLabel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JButton quitterButton;
    private javax.swing.ButtonGroup toggleButtonGroup;
    // End of variables declaration//GEN-END:variables
}