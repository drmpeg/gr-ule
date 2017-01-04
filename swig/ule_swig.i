/* -*- c++ -*- */

#define ULE_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "ule_swig_doc.i"

%{
#include "ule/ule_config.h"
#include "ule/ule_source.h"
%}


%include "ule/ule_config.h"
%include "ule/ule_source.h"
GR_SWIG_BLOCK_MAGIC2(ule, ule_source);
