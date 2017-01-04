/* -*- c++ -*- */
/* 
 * Copyright 2016,2017 Ron Economos.
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

#ifndef INCLUDED_ULE_ULE_SOURCE_H
#define INCLUDED_ULE_ULE_SOURCE_H

#include <ule/api.h>
#include <ule/ule_config.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace ule {

    /*!
     * \brief <+description of block+>
     * \ingroup ule
     *
     */
    class ULE_API ule_source : virtual public gr::sync_block
    {
     public:
      typedef boost::shared_ptr<ule_source> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of ule::ule_source.
       *
       * To avoid accidental use of raw pointers, ule::ule_source's
       * constructor is in a private implementation
       * class. ule::ule_source::make is the public interface for
       * creating new instances.
       */
      static sptr make(char *mac_address, char *filename, char *frequency, ule_ping_reply_t ping_reply, ule_ipaddr_spoof_t ipaddr_spoof, char *src_address, char *dst_address);
    };

  } // namespace ule
} // namespace gr

#endif /* INCLUDED_ULE_ULE_SOURCE_H */

