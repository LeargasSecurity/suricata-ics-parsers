S7comm Keywords
===============

The S7comm application-layer parser (plugin ``s7comm``) exposes keywords for
detecting Siemens S7 (S7comm and S7comm-plus) activity on TCP port 102.

Enable the parser in ``suricata.yaml``:

.. code-block:: yaml

    app-layer:
      protocols:
        s7comm:
          enabled: yes
          detection-ports:
            dp: 102
          # Optional tuning
          # max-tx: 1024              # live transactions cap (DoS guard)
          # max-request-size: 131072  # per-PDU byte cap

Keywords
--------

s7comm.function_code
~~~~~~~~~~~~~~~~~~~~~~

Match on the S7comm function code (Job/Ack-Data parameter). Accepts an 8-bit
unsigned value and the standard uint comparison operators (``=``, ``<``, ``>``,
``<=``, ``>=``, range ``x-y``, bitmask ``&``).

Common values:

==========  ===========================
Value       Function
==========  ===========================
0x04        Read Variable
0x05        Write Variable
0x1a        Request Download
0x1b        Download Block
0x1c        Download Ended
0x1d        Start Upload
0x1e        Upload
0x1f        End Upload
0x28        PLC Control
0x29        PLC Stop
0xf0        Setup Communication
==========  ===========================

Example::

    alert s7comm any any -> any 102 (msg:"S7COMM PLC Stop"; \
        s7comm.function_code:0x29; s7comm.rosctr:1; sid:1;)

s7comm.rosctr
~~~~~~~~~~~~~

Match on the S7comm ROSCTR (remote operating service control, i.e. PDU type).

=====  ==========
Value  PDU type
=====  ==========
1      Job
2      Ack
3      Ack-Data
7      Userdata
=====  ==========

s7comm.dangerous
~~~~~~~~~~~~~~~~~

Boolean keyword (takes no argument). Matches when the transaction's function
code is considered dangerous (writes, program up/download, PLC control, PLC
stop).

Example::

    alert s7comm any any -> any 102 (msg:"S7COMM Dangerous Op"; \
        s7comm.dangerous; s7comm.rosctr:1; sid:1;)

s7comm.userdata_group
~~~~~~~~~~~~~~~~~~~~~~~

Match on the Userdata function group (ROSCTR 7).

=====  ===================
Value  Group
=====  ===================
0      Mode Transition
1      Programmer Commands
2      Cyclic Data
3      Block Functions
4      CPU Functions
5      Security
6      PBC BSEND/BRECV
7      Time Functions
=====  ===================

s7comm.subfunction
~~~~~~~~~~~~~~~~~~~

Match on the Userdata subfunction (8-bit). For example, CPU Functions group
(4) subfunction 1 is *Read SZL* (system status list enumeration).

s7comm.db
~~~~~~~~~

Match on the data block number referenced by a Read/Write Variable request
(16-bit). Only matches transactions that carry an S7ANY data item.

Example — alert on any write to DB100::

    alert s7comm any any -> any 102 (msg:"S7COMM Write DB100"; \
        s7comm.function_code:0x05; s7comm.db:100; sid:1;)

s7comm.area
~~~~~~~~~~~

Match on the memory area referenced by a Read/Write Variable request (8-bit).

=====  =====================
Value  Area
=====  =====================
0x81   Inputs (I)
0x82   Outputs (Q)
0x83   Flags / Merkers (M)
0x84   Data Block (DB)
0x85   Instance DB (DI)
0x86   Local Data (L)
0x1c   Counter
0x1d   Timer
=====  =====================

Example — alert on writes to the process output image::

    alert s7comm any any -> any 102 (msg:"S7COMM Write Outputs"; \
        s7comm.function_code:0x05; s7comm.area:0x82; sid:1;)

s7comm.plus
~~~~~~~~~~~

Boolean keyword (takes no argument). Matches S7comm-plus (v2/v3) traffic used
by S7-1200/1500 PLCs.

s7comm.plus_function
~~~~~~~~~~~~~~~~~~~~~~

Match on the S7comm-plus function code (16-bit) for Request/Response opcodes.

======  ==================
Value   Function
======  ==================
0x04b1  Explore
0x04bb  CreateObject
0x04d4  DeleteObject
0x04f2  SetVariable
0x0542  SetMultiVariables
0x054c  GetMultiVariables
======  ==================

s7comm.data
~~~~~~~~~~~

Sticky buffer holding the raw S7comm PDU payload (request or response depending
on direction). Use with ``content``, ``pcre``, ``byte_test`` and other payload
keywords.

Example::

    alert s7comm any any -> any 102 (msg:"S7COMM payload match"; \
        s7comm.data; content:"|32 01|"; sid:1;)

Frames
------

The parser registers the following frames (usable with the ``frame`` keyword):

=========  ================================================
Frame      Description
=========  ================================================
pdu        The entire TPKT/COTP/S7comm PDU
s7comm     The S7comm portion (after TPKT and COTP headers)
=========  ================================================

Events
------

The parser sets the following app-layer events (match with ``app-layer-event``):

- ``malformed_pdu``
- ``invalid_protocol_id``
- ``plc_stop``
- ``plc_mode_change``
- ``program_download``
- ``program_upload``
- ``write_variable``
- ``read_szl``
- ``password_access``
- ``s7_comm_plus_usage``
- ``too_many_transactions``
