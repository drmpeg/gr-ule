/* -*- c++ -*- */
/* 
 * Copyright 2017 Ron Economos.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_ULE_ULE_CONFIG_H
#define INCLUDED_ULE_ULE_CONFIG_H

namespace gr {
  namespace ule {
    enum ule_ping_reply_t {
      PING_REPLY_OFF = 0,
      PING_REPLY_ON,
    };

    enum ule_ipaddr_spoof_t {
      IPADDR_SPOOF_OFF = 0,
      IPADDR_SPOOF_ON,
    };

  } // namespace ule
} // namespace gr

typedef gr::ule::ule_ping_reply_t ule_ping_reply_t;
typedef gr::ule::ule_ipaddr_spoof_t ule_ipaddr_spoof_t;

#endif /* INCLUDED_ULE_ULE_CONFIG_H */

