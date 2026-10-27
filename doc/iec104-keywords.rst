IEC 60870-5-104 Keywords
========================

The IEC 60870-5-104 application-layer parser (app-layer protocol ``iec104``)
exposes keywords for detecting telecontrol activity on TCP port 2404. It ships
in the same plugin library as the S7comm parser.

Enable the parser in ``suricata.yaml``:

.. code-block:: yaml

    app-layer:
      protocols:
        iec104:
          enabled: yes
          detection-ports:
            dp: 2404
          # Optional tuning
          # max-tx: 1024   # live transactions cap (DoS guard)

Every APDU (I, S or U format) becomes one unidirectional transaction. ASDU
keywords only match I-format APDUs; ``iec104.u_function`` only matches
U-format APDUs.

Keywords
--------

type-id
~~~~~~~

``iec104.type_id`` matches the ASDU type identification (uint8). Supports the
standard uint operators (``=``, ``<``, ``>``, ``<=``, ``>=``, ``x-y``
exclusive range, bitmask ``&``).

=======  ============  ==================================
Value    Name          Meaning
=======  ============  ==================================
1        M_SP_NA_1     Single-point information
3        M_DP_NA_1     Double-point information
13       M_ME_NC_1     Measured value, short float
30       M_SP_TB_1     Single-point with CP56Time2a
45       C_SC_NA_1     Single command
46       C_DC_NA_1     Double command
47       C_RC_NA_1     Regulating step command
48       C_SE_NA_1     Setpoint, normalized
49       C_SE_NB_1     Setpoint, scaled
50       C_SE_NC_1     Setpoint, short float
51       C_BO_NA_1     Bitstring of 32 bit
58-64    C_xx_TA_1     Time-tagged variants of 45-51
100      C_IC_NA_1     General interrogation
101      C_CI_NA_1     Counter interrogation
102      C_RD_NA_1     Read command
103      C_CS_NA_1     Clock synchronization
105      C_RP_NA_1     Reset process
110-113  P_xx          Parameter / parameter activation
120-127  F_xx          File transfer
=======  ============  ==================================

Example::

    alert iec104 any any -> any 2404 (msg:"IEC104 Single Command"; \
        iec104.type_id:45; iec104.cot:6; sid:1;)

cot
~~~

``iec104.cot`` matches the cause of transmission (uint8, 6-bit value; the
P/N and test bits are excluded).

=====  =================================
Value  Cause
=====  =================================
3      Spontaneous
5      Request
6      Activation
7      Activation confirmation
8      Deactivation
10     Activation termination
20     Interrogated by station
44-47  Unknown type / COT / CA / IOA
=====  =================================

common-address
~~~~~~~~~~~~~~

``iec104.common_address`` matches the common address of the ASDU (uint16,
station address).

ioa
~~~

``iec104.ioa`` matches the information object address (uint32, 24-bit value).
It matches if **any** information object in the ASDU satisfies the condition.
For variable-length types (``F_SG_NA_1``) or unknown types only the first IOA
is considered.

Example::

    alert iec104 any any -> any 2404 (msg:"IEC104 command to breaker IOA 5000"; \
        iec104.type_id:45; iec104.ioa:5000; sid:1;)

u-function
~~~~~~~~~~

``iec104.u_function`` matches the first control octet of a U-format APDU.

=====  ============
Value  Function
=====  ============
0x07   STARTDT act
0x0b   STARTDT con
0x13   STOPDT act
0x23   STOPDT con
0x43   TESTFR act
0x83   TESTFR con
=====  ============

dangerous
~~~~~~~~~

``iec104.dangerous`` takes no argument. It matches control commands
(types 45-51, 58-64) and parameter changes (110-113) with COT activation or
deactivation, and reset-process commands (105) with COT activation.

data
~~~~

``iec104.data`` is a sticky buffer containing the raw APDU (start byte through
end of ASDU) for ``content``/``pcre`` matching.

Frames
------

``iec104.pdu`` (whole APDU) and ``iec104.asdu`` (ASDU portion of I-format
APDUs) are available to the ``frame`` keyword.

App-layer events
----------------

``malformed_apdu``, ``invalid_start_byte``, ``invalid_length``,
``unknown_u_function``, ``unknown_type_id``, ``invalid_cot``,
``asdu_length_mismatch``, ``sequence_mismatch``, ``negative_confirmation``,
``unknown_address``, ``command``, ``interrogation``, ``clock_sync``,
``reset_process``, ``parameter_change``, ``file_transfer``,
``stop_data_transfer``, ``too_many_transactions``.

Example::

    alert iec104 any any -> any any (msg:"IEC104 N(S) discontinuity"; \
        app-layer-event:iec104.sequence_mismatch; sid:1;)
