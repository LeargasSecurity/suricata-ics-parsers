MMS Keywords
============

The MMS application-layer parser (app-layer protocol ``mms``) decodes MMS
(ISO 9506) over the OSI stack on TCP port 102: TPKT (RFC 1006), COTP
(ISO 8073, with DT reassembly), ISO 8327 session, ISO 8823 presentation, ACSE
(ISO 8650) and MMS. It covers IEC 61850 client/server traffic and ICCP /
TASE.2 (IEC 60870-6) between control centres. It ships in the same plugin
library as the S7comm parser.

Enable the parser in ``suricata.yaml``:

.. code-block:: yaml

    app-layer:
      protocols:
        mms:
          enabled: yes
          detection-ports:
            dp: 102
          # Optional tuning
          # max-tx: 1024                 # live transactions cap (DoS guard)
          # max-message-size: 1048576    # reassembled COTP message cap

S7comm and MMS share port 102 and the same COTP connection handshake.
Protocol detection skips the COTP CR/CC and looks at the first COTP DT
payload: S7comm (``0x32``) and S7comm-Plus (``0x72``) go to ``s7comm``; an
ISO 8327 session SPDU, or an MMS PDU carried directly on COTP (reduced stack,
as some tools and scanners send it), goes to ``mms``; anything else ends as
``failed``. A malformed TPKT frame is reported as ``malformed_pdu`` and does
not disable inspection of the rest of the flow.

Transactions
------------

* A confirmed request and its response, error or reject, matched by invoke
  ID and direction, form one transaction. A cancel request is paired with its
  cancel response or error.
* The association (ACSE AARQ/AARE carrying the MMS initiate PDUs), the MMS
  initiate and conclude exchanges, and the ACSE release (RLRQ/RLRE) are
  request/response transactions.
* Unconfirmed PDUs (InformationReport, ...) and aborts are single-message
  transactions, as is a reject without an invoke ID or matching request.
* A request is closed without a response when its response direction has a
  stream gap, or when the flow reaches ``max-tx`` live transactions: then all
  pending requests are closed (so they are logged and freed),
  ``too_many_transactions`` is raised once, and parsing continues.

MMS requests can travel in either direction: in ICCP both control centres
act as clients. Request keywords (``mms.service``, ``mms.dangerous``,
``mms.iccp_transfer_set``, ``mms.domain``, ``mms.item``, ``mms.filename``)
match in the direction the request was sent, once per transaction, so rules
do not need a ``flow`` direction.

Keywords
--------

pdu-type
~~~~~~~~

``mms.pdu_type`` matches the MMS PDU type (uint8) of the request in the
request direction and of the response in the response direction. It accepts a
number with the standard uint operators, or one of these names:

=====  ======================
Value  Name
=====  ======================
0      ``confirmed_request``
1      ``confirmed_response``
2      ``confirmed_error``
3      ``unconfirmed``
4      ``reject``
5-7    ``cancel_request``, ``cancel_response``, ``cancel_error``
8-10   ``initiate_request``, ``initiate_response``, ``initiate_error``
11-13  ``conclude_request``, ``conclude_response``, ``conclude_error``
=====  ======================

Example::

    alert mms any any -> any any (msg:"MMS confirmed error"; \
        flow:to_client; mms.pdu_type:confirmed_error; sid:1;)

service
~~~~~~~

``mms.service`` matches the confirmed service (ConfirmedServiceRequest tag,
uint8). It accepts a number with the standard uint operators (``x-y`` is an
exclusive range), or a service name as in ISO 9506-2 (case-insensitive):

=====  ===================================
Value  Name
=====  ===================================
1      ``getNameList``
2      ``identify``
4      ``read``
5      ``write``
6      ``getVariableAccessAttributes``
11     ``defineNamedVariableList``
12     ``getNamedVariableListAttributes``
13     ``deleteNamedVariableList``
26-28  ``initiateDownloadSequence``, ``downloadSegment``,
       ``terminateDownloadSequence``
29-31  ``initiateUploadSequence``, ``uploadSegment``,
       ``terminateUploadSequence``
32-35  ``requestDomainDownload``, ``requestDomainUpload``,
       ``loadDomainContent``, ``storeDomainContent``
36     ``deleteDomain``
38-44  ``createProgramInvocation``, ``deleteProgramInvocation``, ``start``,
       ``stop``, ``resume``, ``reset``, ``kill``
46     ``obtainFile``
65-70  ``readJournal``, ``writeJournal``, ``initializeJournal``,
       ``reportJournalStatus``, ``createJournal``, ``deleteJournal``
72-77  ``fileOpen``, ``fileRead``, ``fileClose``, ``fileRename``,
       ``fileDelete``, ``fileDirectory``
=====  ===================================

All 78 ISO 9506-2 confirmed services (0-77) are accepted by name.

Example::

    alert mms any any -> any any (msg:"MMS program stop/start"; \
        mms.service:>=40; mms.service:<=44; sid:1;)

dangerous
~~~~~~~~~

``mms.dangerous`` takes no argument. It matches requests that act on the
process or the device:

* writes to IEC 61850 control objects (``$CO$``) and settings (``$SP$``,
  ``$SG$``, ``$SE$``);
* ``start``, ``stop``, ``resume``, ``reset``, ``kill``;
* domain downloads (``initiateDownloadSequence``, ``downloadSegment``,
  ``terminateDownloadSequence``, ``requestDomainDownload``,
  ``loadDomainContent``);
* ``deleteDomain``, ``deleteProgramInvocation``, ``deleteNamedVariableList``,
  ``deleteVariableAccess``, ``fileDelete``, ``obtainFile``,
  ``initializeJournal`` and ``deleteJournal``.

Writes to report and log control blocks (``$RP$``, ``$BR$``, ``$LG$``) are
client configuration and are not dangerous.

iccp-transfer-set
~~~~~~~~~~~~~~~~~

``mms.iccp_transfer_set`` takes no argument. It matches writes to an ICCP
(TASE.2) data set transfer set. Transfer set names are site-specific: a
client obtains one by reading ``Next_DSTransfer_Set``, then writes to it to
configure which data the remote control centre is sent and when. The parser
remembers the names returned by those reads in the flow and flags later
writes to them.

domain, item, filename
~~~~~~~~~~~~~~~~~~~~~~

``mms.domain``, ``mms.item`` and ``mms.filename`` are sticky multi-buffers for
``content``/``pcre`` matching against the request:

* ``mms.item``: object names (the item of a domain-specific name, or a VMD/AA
  specific name), for example ``GGIO1$CO$SPCSO1$Oper``;
* ``mms.domain``: domain names of the objects, the domain scope of
  ``getNameList`` and ``deleteNamedVariableList``, and the domain or program
  invocation named by domain and program services;
* ``mms.filename``: file names, with path components joined by ``/``.

Example::

    alert mms any any -> any any (msg:"IEC61850 control operate on breaker XCBR"; \
        mms.service:write; mms.item; content:"XCBR"; content:"$CO$"; \
        content:"$Oper"; distance:0; sid:1;)

Frames
------

``mms.pdu`` (one TPKT frame: TPKT, COTP and its user data segment) is
available to the ``frame`` keyword.

App-layer events
----------------

``malformed_pdu``, ``message_too_large``, ``too_many_transactions``,
``association_rejected``, ``authentication``, ``control_operation``,
``setting_change``, ``data_set_change``, ``iccp_transfer_set_write``,
``program_control``, ``program_download``, ``program_upload``,
``domain_delete``, ``file_delete``, ``file_rename``, ``file_transfer``,
``journal_change``, ``reject``, ``abort``.

Request/response transactions are inspected in both directions, so an
``app-layer-event`` rule for an event raised on such a transaction matches
once per direction unless it is limited with ``flow``. ``authentication`` is
raised on the AARQ (``flow:to_server``) and ``association_rejected`` on the
AARE (``flow:to_client``). For the request-side classifications prefer the
keywords above (``mms.service``, ``mms.item``, ``mms.dangerous``,
``mms.iccp_transfer_set``), which match once, and ``mms.pdu_type:reject``
for rejects. Events on single-message transactions (``malformed_pdu``,
``message_too_large``, ``too_many_transactions``, ``abort``) match once.

Example::

    alert mms any any -> any any (msg:"MMS message too large"; \
        app-layer-event:mms.message_too_large; sid:1;)

EVE logging
-----------

Enable the ``mms`` EVE type. Each transaction is logged with its ``request``
and ``response`` (when present), each carrying its ``direction``:

* MMS: ``pdu_type``, ``invoke_id``, ``service``, ``objects`` (``scope``,
  ``domain``, ``item``), ``members`` (variables of a defined data set),
  ``object_class`` and ``domain`` (``getNameList``), ``names`` (domains or
  program invocations), ``files``, ``success_count``/``failure_count`` (read
  and write responses), ``error`` (``class``, ``code``), ``reject`` and
  ``initiate`` (negotiated ``max_pdu_size``, outstanding requests, nesting
  level, ``version``);
* ACSE: ``acse`` (``aarq``, ``aare``, ``rlrq``, ``rlre``, ``abrt``),
  ``application_context``, called/calling (or responding) AP titles and AE
  qualifiers, ``authentication_mechanism``, ``authentication`` (true when a
  value such as a password is present; the value itself is never logged),
  ``result`` and ``reason``.

The transaction also carries ``session`` (the ISO 8327 SPDU type),
``is_dangerous``, ``attack_technique`` and, for transfer set writes,
``iccp_transfer_set``.
