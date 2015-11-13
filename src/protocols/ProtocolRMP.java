/**
 * ProtocolRMP
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

package protocols;

import beans.BeanDBAccessMySQL;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import serveur_reservations.Serveur_Reservations;

/**
 * Manage a {@link ProtocolRMP}
 * @author Sh1fT
 */
public class ProtocolRMP implements interfaces.ProtocolRMP {
    private Serveur_Reservations parent;
    private BeanDBAccessMySQL bdbam;
    public static final int RESPONSE_OK = 100;
    public static final int RESPONSE_KO = 600;

    /**
     * Create a new {@link ProtocolRMP} instance
     * @param parent 
     */
    public ProtocolRMP(Serveur_Reservations parent) {
        this.setParent(parent);
        this.setBdbam(new BeanDBAccessMySQL(
                System.getProperty("file.separator") +"properties" +
                System.getProperty("file.separator") + "BeanDBAccessMySQL.properties"));
    }

    public Serveur_Reservations getParent() {
        return parent;
    }

    public void setParent(Serveur_Reservations parent) {
        this.parent = parent;
    }

    public BeanDBAccessMySQL getBdbam() {
        return bdbam;
    }

    public void setBdbam(BeanDBAccessMySQL bdbam) {
        this.bdbam = bdbam;
    }

    /**
     * Effectue la connexion pour un gestionnaire de chambres
     * @param name
     * @param password
     * @return 
     */
    @Override
    public Integer login(String name, String password) {
        try {
            String query = "SELECT * FROM gestionnairechambres WHERE nom LIKE ? " +
                "AND password LIKE ?;";
            PreparedStatement ps = this.getBdbam().getDBConnection().prepareStatement(query);
            ps.setString(1, name);
            ps.setString(2, password);
            ResultSet rs = this.getBdbam().executeQuery(ps);
            if (rs.next())
                return ProtocolRMP.RESPONSE_OK;
            return ProtocolRMP.RESPONSE_KO;
        } catch (SQLException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            this.getBdbam().stop();
            System.exit(1);
        }
        return null;
    }

    /**
     * Réservation d'une chambre
     * @param category
     * @param type
     * @param arrival
     * @param nights
     * @param clientName
     * @return 
     */
    @Override
    public String bookingRoom(String category, String type, Date arrival,
            Integer nights, String clientName) {
        try {
            String query = "SELECT idChambre FROM chambres WHERE " +
                "categorieChambre LIKE ? AND typeChambre LIKE ?;";
            PreparedStatement ps = this.getBdbam().getDBConnection().prepareStatement(query);
            ps.setString(1, category);
            ps.setString(2, type);
            ResultSet rs = this.getBdbam().executeQuery(ps);
            String idChambre = null;
            if (rs.next()) {
                idChambre = rs.getString("idChambre");
                query = "SELECT idVoyageur FROM voyageurs WHERE nom LIKE ?;";
                ps = this.getBdbam().getDBConnection().prepareStatement(query);
                ps.setString(1, clientName);
                rs = this.getBdbam().executeQuery(ps);
                Integer idVoyageur = null;
                if (rs.next()) {
                    idVoyageur = rs.getInt("idVoyageur");
                    query = "INSERT INTO reservations VALUES(0, ?, ?, 0, ?, ?, 0);";
                    ps = this.getBdbam().getDBConnection().prepareStatement(query);
                    ps.setString(1, idChambre);
                    ps.setInt(2, idVoyageur);
                    ps.setDate(3, arrival);
                    ps.setInt(4, nights);
                    Integer rss = this.getBdbam().executeUpdate(ps);
                    if (rss == 1) {
                        this.getBdbam().getDBConnection().commit();
                        return idChambre;
                    } else
                        return "KO";
                }
            }
        } catch (SQLException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            this.getBdbam().stop();
            System.exit(1);
        }
        return null;
    }

    /**
     * Accord et paiement de la réservation
     * @param idRoom
     * @param clientName
     * @param creditCard
     * @return 
     */
    @Override
    public Integer payRoom(String idRoom, String clientName, String creditCard) {
        try {
            String query = "SELECT idVoyageur FROM voyageurs WHERE nom LIKE ?;";
            PreparedStatement ps = this.getBdbam().getDBConnection().prepareStatement(query);
            ps.setString(1, clientName);
            ResultSet rs = this.getBdbam().executeQuery(ps);
            Integer idVoyageur = null;
            if (rs.next()) {
                idVoyageur = rs.getInt("idVoyageur");
                query = "UPDATE reservations SET paye = 1 WHERE chambre LIKE ? " +
                    "AND voyageurTitulaire = ?";
                ps = this.getBdbam().getDBConnection().prepareStatement(query);
                ps.setString(1, idRoom);
                ps.setInt(2, idVoyageur);
                Integer rss = this.getBdbam().executeUpdate(ps);
                if (rss == 1) {
                    this.getBdbam().getDBConnection().commit();
                    return ProtocolRMP.RESPONSE_OK;
                } else
                    return ProtocolRMP.RESPONSE_KO;
            }
        } catch (SQLException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            this.getBdbam().stop();
            System.exit(1);
        }
        return null;
    }

    /**
     * Suppression d'une réservation de chambre
     * @param idRoom
     * @param clientName
     * @return 
     */
    @Override
    public Integer cancelRoom(String idRoom, String clientName) {
        try {
            String query = "SELECT idVoyageur FROM voyageurs WHERE nom LIKE ?;";
            PreparedStatement ps = this.getBdbam().getDBConnection().prepareStatement(query);
            ps.setString(1, clientName);
            ResultSet rs = this.getBdbam().executeQuery(ps);
            Integer idVoyageur = null;
            if (rs.next()) {
                idVoyageur = rs.getInt("idVoyageur");
                query = "DELETE FROM reservations WHERE chambre LIKE ? " +
                    "AND voyageurTitulaire = ?;";
                ps = this.getBdbam().getDBConnection().prepareStatement(query);
                ps.setString(1, idRoom);
                ps.setInt(2, idVoyageur);
                Integer rss = this.getBdbam().executeUpdate(ps);
                if (rss == 1) {
                    this.getBdbam().getDBConnection().commit();
                    return ProtocolRMP.RESPONSE_OK;
                } else
                    return ProtocolRMP.RESPONSE_KO;
            }
        } catch (SQLException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            this.getBdbam().stop();
            System.exit(1);
        }
        return null;
    }

    /**
     * Liste des chambres d'hôtel réservées à ce jour
     * @return 
     */
    @Override
    public String listRooms() {
        try {
            String listRooms = "";
            String query = "SELECT chambre, nom FROM reservations, voyageurs WHERE " +
                "reservations.voyageurTitulaire = voyageurs.idVoyageur AND " +
                "EXTRACT(DAY FROM reservations.dateArrivee) = EXTRACT(DAY FROM CURRENT_DATE) " +
                " AND EXTRACT(MONTH FROM reservations.dateArrivee) = EXTRACT(MONTH FROM CURRENT_DATE) " +
                " AND EXTRACT(YEAR FROM reservations.dateArrivee) = EXTRACT(YEAR FROM CURRENT_DATE);";
            ResultSet rs = this.getBdbam().executeQuery(query);
            while (rs.next())
                listRooms += rs.getString("chambre") + ":" + rs.getString("nom") + ":";
            return listRooms;
        } catch (SQLException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            this.getBdbam().stop();
            System.exit(1);
        }
        return null;
    }
}