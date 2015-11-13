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

package interfaces;

import java.sql.Date;

/**
 * Manage a {@link ProtocolRMP}
 * @author Sh1fT
 */
public interface ProtocolRMP {
    public Integer login(String name, String password);
    public String bookingRoom(String category, String type, Date arrival,
        Integer nights, String clientName);
    public Integer payRoom(String idRoom, String clientName, String creditCard);
    public Integer cancelRoom(String idRoom, String clientName);
    public String listRooms();
}