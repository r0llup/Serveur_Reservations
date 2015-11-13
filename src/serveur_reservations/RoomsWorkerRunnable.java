/**
 * RoomsWorkerRunnable
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

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.sql.Date;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.xml.sax.InputSource;
import protocols.ProtocolRMP;

/**
 * Manage a {@link RoomsWorkerRunnable}
 * @author Sh1fT
 */
public class RoomsWorkerRunnable implements Runnable {
    private Serveur_Reservations parent;
    private Socket cSocket;

    /**
     * Create a new {@link RoomsWorkerRunnable} instance
     * @param parent
     * @param cSocket 
     */
    public RoomsWorkerRunnable(Serveur_Reservations parent, Socket cSocket) {
        this.setParent(parent);
        this.setcSocket(cSocket);
    }

    public Serveur_Reservations getParent() {
        return parent;
    }

    public void setParent(Serveur_Reservations parent) {
        this.parent = parent;
    }

    public Socket getcSocket() {
        return cSocket;
    }

    public void setcSocket(Socket cSocket) {
        this.cSocket = cSocket;
    }

    public void run() {
        try {
            this.getParent().getClientLabel().setText(
                    this.getcSocket().getInetAddress().getHostAddress());
            InputSource is = new InputSource(new InputStreamReader(
                    this.getcSocket().getInputStream()));
            BufferedReader br = new BufferedReader(is.getCharacterStream());
            ObjectOutputStream oos = new ObjectOutputStream(
                    this.getcSocket().getOutputStream());
            String cmd = br.readLine();
            if (cmd.contains("EXCHKEY")) {
                this.getParent().setClientPublicKey(
                        Base64.decode(cmd.split(":")[1]));
                oos.writeObject(this.getParent().getKeyPair().getPublic());
            } else if (cmd.contains("SENDKEY")) {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
                cipher.init(Cipher.DECRYPT_MODE,
                        this.getParent().getKeyPair().getPrivate());
                this.getParent().setSecretKey(new SecretKeySpec(cipher.doFinal(
                        Base64.decode(cmd.split(":")[1])), "AES"));
                oos.writeObject("OK");
            } else if (cmd.contains("LOGIN")) {
                String username = cmd.split(":")[1];
                String password = cmd.split(":")[2];
                Integer res = this.getParent().getProtocolRMP().
                        login(username, password);
                switch (res) {
                    case ProtocolRMP.RESPONSE_OK:
                        oos.writeObject("OK");
                        break;
                    case ProtocolRMP.RESPONSE_KO:
                        oos.writeObject("KO");
                        break;
                    default:
                        oos.writeObject("KO");
                        break;
                }
            } else if (cmd.contains("BROOM")) {
                String category = cmd.split(":")[1];
                String type = cmd.split(":")[2];
                SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yy");
                Date arrival = new Date(sdf.parse(cmd.split(":")[3]).getTime());
                Integer nights = Integer.parseInt(cmd.split(":")[4]);
                String clientName = this.getParent().decryptClientName(
                        cmd.split(":")[5]);
                String signature = cmd.split(":")[6];
                String res = null;
                if (this.getParent().verifySignature(signature, "BROOM_SIG",
                        this.getParent().getClientPublicKey()))
                    res = this.getParent().getProtocolRMP().
                            bookingRoom(category, type, arrival, nights, clientName);
                else
                    res = "KO";
                oos.writeObject(res);
            } else if (cmd.contains("PROOM")) {
                String idRoom = cmd.split(":")[1];
                String clientName = this.getParent().decryptClientName(
                        cmd.split(":")[2]);
                String creditCard = cmd.split(":")[3];
                String signature = cmd.split(":")[4];
                Integer res = null;
                if (this.getParent().verifySignature(signature, "PROOM_SIG",
                        this.getParent().getClientPublicKey())) {
                    res = this.getParent().getProtocolRMP().
                        payRoom(idRoom, clientName, creditCard);
                    SSLSocketFactory factory =
                            (SSLSocketFactory) SSLSocketFactory.getDefault();
                    SSLSocket socket = (SSLSocket) factory.createSocket(
                            this.getParent().getCreditServerHost(),
                            this.getParent().getCreditServerPort());
                    final String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
                    socket.setEnabledCipherSuites(enabledCipherSuites);
                    PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                            socket.getOutputStream()), true);
                    ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                    pw.println("PAY_FOR_CLIENT:" + creditCard);
                    String response = (String) ois.readObject();
                    if (response.equals("OK")) {
                        if (res == ProtocolRMP.RESPONSE_OK) {
                            socket = (SSLSocket) factory.createSocket(
                                    this.getParent().getBanqueServerHost(),
                                    this.getParent().getBanqueServerPort());
                            socket.setEnabledCipherSuites(enabledCipherSuites);
                            pw = new PrintWriter(new OutputStreamWriter(
                            socket.getOutputStream()), true);
                            ois = new ObjectInputStream(socket.getInputStream());
                            pw.println("TRANSFER_POGN:31337.37:" + clientName);
                            String response2 = (String) ois.readObject();
                            if (response2.equals("OK"))
                                res = ProtocolRMP.RESPONSE_OK;
                            else
                                res = ProtocolRMP.RESPONSE_KO;
                        } else
                            res = ProtocolRMP.RESPONSE_KO;
                    } else
                        res = ProtocolRMP.RESPONSE_KO;
                    ois.close();
                    pw.close();
                    socket.close();
                } else
                    res = ProtocolRMP.RESPONSE_KO;
                switch (res) {
                    case ProtocolRMP.RESPONSE_OK:
                        oos.writeObject("OK");
                        break;
                    case ProtocolRMP.RESPONSE_KO:
                        oos.writeObject("KO");
                        break;
                    default:
                        oos.writeObject("KO");
                        break;
                }
            } else if (cmd.contains("CROOM")) {
                String idRoom = cmd.split(":")[1];
                String clientName = this.getParent().decryptClientName(
                        cmd.split(":")[2]);
                String signature = cmd.split(":")[3];
                Integer res = null;
                if (this.getParent().verifySignature(signature, "CROOM_SIG",
                        this.getParent().getClientPublicKey()))
                    res = this.getParent().getProtocolRMP().
                        cancelRoom(idRoom, clientName);
                else
                    res = ProtocolRMP.RESPONSE_KO;
                switch (res) {
                    case ProtocolRMP.RESPONSE_OK:
                        oos.writeObject("OK");
                        break;
                    case ProtocolRMP.RESPONSE_KO:
                        oos.writeObject("KO");
                        break;
                    default:
                        oos.writeObject("KO");
                        break;
                }
            } else if (cmd.contains("LROOMS")) {
                String res = this.getParent().getProtocolRMP().
                        listRooms();
                oos.writeObject(this.getParent().encryptClientName(res));
            }
            oos.close();
            br.close();
            this.getcSocket().close();
            this.getParent().getClientLabel().setText("aucun");
        } catch (IOException | ParseException | NoSuchAlgorithmException |
                NoSuchProviderException | IllegalBlockSizeException |
                InvalidKeyException | NoSuchPaddingException |
                BadPaddingException | ClassNotFoundException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
    }
}