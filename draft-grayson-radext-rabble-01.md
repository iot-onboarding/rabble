---
title: RADIUS profile for Bonded Bluetooth Low Energy peripherals
abbrev: RABBLE
docname: draft-grayson-radext-rabble-01
date: 2023-04-26
category: std
submissiontype: IETF

ipr: trust200902
area: General
workgroup: RADEXT Working Group
keyword:
  - Internet-Draft
  - Bluetooth Low Energy
  - RADIUS

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: M. Grayson
    name: Mark Grayson
    organization: Cisco Systems
    street: 10 New Square Park
    city: Feltham
    code: TW14 8HA
    country: UK
    email: mgrayson@cisco.com
 -
    ins: E. Lear
    name: Eliot Lear
    organization: Cisco Systems
    street: Glatt-com
    city: CH-8301 Glattzentrum, Zurich
    country: CH
    email: elear@cisco.com

normative:
  RFC2119:
  RFC2865:
  RFC3580:
  RFC4086:
  RFC4868:
  RFC8174:
  RFC6455:
  RFC5580:
  RFC6929:
  I-D.draft-dekok-radext-deprecating-radius:

informative:
  RFC2866:
  RFC3394:
  RFC7585:
  I-D.shahzad-scim-device-model:
  BLUETOOTH:
    title: BLUETOOTH CORE SPECIFICATION v5.3
    target: https://www.bluetooth.com/specifications/bluetooth-core-specification/
    author:
      ins: Bluetooth Core Specification Working Group
    date: 2021-07-13
  MQTT:
    title: MQTT Version 5.0
    target: https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html
    author:
      ins: OASIS
    date: 2019-03-07


--- abstract

This document specifies an extension to the Remote Authentication
Dial-In User Service (RADIUS) protocol that enables a Bluetooth
Low Energy (BLE) peripheral device that has previously formed a bonded,
secure trusted relationship with a first "home" Bluetooth Low Energy Central
device to operate with a second "visited" Bluetooth Low Energy Central device.

--- middle

Introduction        {#problems}
============

This document specifies an extension to the Remote Authentication
Dial-In User Service (RADIUS) protocol {{RFC2865}} that enables a Bluetooth
Low Energy (BLE) peripheral device that has previously formed a bonded,
secure trusted relationship with a first "home" Bluetooth Low Energy Central
device to operate with a second "visited" Bluetooth Low Energy Central device
that is integrated with a Network Access Server.

After being successfully authenticated, a signalling link is established
that enables Bluetooth messages advertised by the BLE Peripheral to be forwarded
from the Visited Bluetooth Low Energy Central device to a Home MQTT Broker.
For connectable BLE Peripherals, the signalling link enables the Home MQTT
Broker to send BLE Requests or Commands to the Visited Bluetooth Low Energy
Central device that is then responsible for forwarding to the BLE peripheral.

The extensions allow administrative entities to collaborate to enable
RADIUS authentication of BLE devices onto their respective networks, without
requiring the peripheral to perform a re-pairing on the visited network.

Requirements Language          {#Requirements}
-----------
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL",
"SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT
RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.


Terminology          {#Terminology}
-----------

BLE Central Controller:

  The BLE entity that implements the Bluetooth Link Layer and interacts
  with the Bluetooth Radio Hardware.

BLE Central Host:

  A BLE entity that interacts with the BLE Central Controller to enable applications
  to communicate with peer BLE devices in a standard and interoperable way.

BLE Peripheral Device:

  A BLE device that is configured to repeatedly send advertising messages.  

BLE Security Database:

  A database that stores the keying material associated with a
  bonded Bluetooth Connection.

Bluetooth Low Energy (BLE):

  A wireless technology designed for low power operation and specified by the Bluetooth Special Interest Group.

Bonding:

  A Bluetooth {{BLUETOOTH}} defined process that creates a relation between
  a Bluetooth Central device and a Bluetooth Peripheral device which generates session keying material that is expected
  to be stored by both Bluetooth devices, to be used for future authentication.

Hash:

  A Bluetooth {{BLUETOOTH}} specified 24-bit hash value which is calculated using a
  hash function operating on IRK and prand as its input parameters. The hash is encoded
  in the 24 least significant bits of a Resolvable Private Address.

Home:

  A network that has access to the keying material necessary to support the pairing of a
  BLE peripheral and that is able to expose the keys generated as part of the BLE bonding
  process.

Identity Address (IA):

  The 48-bit global (public) MAC address of a Bluetooth device.

Identity Resolving Key (IRK):

  A Bluetooth {{BLUETOOTH}} specified key used in the Bluetooth privacy feature.
  The Resolvable Private Address hash value is calculated using a hash function of prand and the IRK.

Long-Term  key (LTK):

  A symmetric key which is generated during the Bluetooth bonding procedure and
  used to generate the session key used to encrypt a communication session between Bluetooth devices.

prand:

  A 24-bit random number used by a BLE device to
  generate a Resolvable Private Address. The prand is encoded in the  24 most
  significant bits of a Resolvable Private Address.

Resolvable Private Address (RPA):

  A Bluetooth {{BLUETOOTH}} specified private 48-bit address that can be
  resolved to a permanent Bluetooth Identity Address through the
  use of an Identity Resolving Key.

Visited:

  A network that does not have access to the keying material necessary to support the pairing of a
  BLE peripheral, but that is able to support the RADIUS authentication of an already bonded BLE Peripheral.


BLE Roaming Overview
===============

This section provides an overview of the RADIUS BLE mechanism, which
is supported by the extensions described in this document.
The RADIUS profile is intended to be used between a Visited BLE Central Host that
is enhanced with Network Access Server (NAS) functionality which enables
it to exchange messages with a RADIUS server.

~~~~~~~~~~

                 +------------+   +-----------+
+------------+   |     BLE    |   |    BLE    |
|    BLE     |---|  Central#1 |---|   Home    |  
| Peripheral |   | Controller |   | Central#1 |
+------------+   |            |   |   Host    |
                 +------------+   +-----------+   
       |                               |   
       |                               |  
       |            +-------------------------+
       |            |  BLE Security Database  |
       |            |    Peripheral: IA, IRK  |
       |            |            AP: IA, IRK  |
       |            | Peripheral+AP: LTK      |
       |            +-------------------------+
       |                               |  
       | Bonded BLE                    |       
       | Peripheral             +-------------+  
       | moves                  |RADIUS Server|
       |                        +-------------+
      \|/                              |  
       -                               |
                 +------------+   +-----------+
+------------+   |     BLE    |   |  NAS/BLE  |
|    BLE     |---|  Central#2 |---|  Visited  |  
| Peripheral |   | Controller |   | Central#2 |   
+------------+   |            |   |   Host    |
                 +------------+   +-----------+
~~~~~~~~~~
{: #figarch title="BLE RADIUS Authentication Overview"}

A BLE Peripheral is paired and bonded with the BLE Home Central Host.
The pairing requires the BLE Home Central Host to have
access to the keying material necessary to support the pairing of a
BLE peripheral, e.g., by using techniques
described in {{I-D.shahzad-scim-device-model}}.

The bonding process generates new session specific keying material that MUST be exposed
by the BLE Home Central Host to a RADIUS server, e.g., stored in a
BLE Security Database which is accessible by the RADIUS server. The keying
material MUST include the peripheral's IA and IRK, indicating that the BLE Peripheral
has enabled the Bluetooth privacy feature and is operating with a Resolvable Private Address (RPA).

The BLE Peripheral then moves into the coverage of a second
BLE Central device which comprises a second BLE Central Controller and a second BLE
(Visited) Central Host which has been enhanced with Network Access Server (NAS)
functionality. The BLE Peripheral MUST be configured to send low duty cycle
advertising events using the BLE Peripheral's RPA that are detected by the NAS/BLE
Visited Central Host. The NAS/BLE Visited Central Host receives the Advertisement(s) sent by the
BLE Peripheral and MAY use the presence and/or contents of specific Advertising Elements
to decide whether to trigger a RADIUS exchange with a RADIUS Server which has
access to the keying material exposed by the BLE Home Central Host.

The successful authentication of the BLE Peripheral onto the BLE Visited Central
Host MUST include the signalling of the keying material exposed by the
BLE Home Central Host to enable the
re-establishment of the secured communication session with the BLE Peripheral.
Bluetooth advertisements received from an authenticated BLE Peripheral are
forwarded between the BLE Visited Central Host and a Home MQTT message broker.

If the BLE Peripheral is connectable, the Home MQTT Broker MAY send
BLE Requests or Commands to the Visited Bluetooth Low Energy Central device
that is then responsible for forwarding to the authenticated BLE peripheral.
The Home MQTT Broker MAY be configured to forward the messages
to/from a Bluetooth Application associated with the authenticated BLE Peripheral,
either directly, or via the first Home Bluetooth Low Energy Central device.


~~~~~~~~~~
                                   +-----------+
                                   |    BLE    |
                          +--------|Application|
                          |        +-----------+
                          |              |       
                          |              |       
                          |        +-----------+
          Optional direct |        | BLE Home  |
       signalling between |        | Central#1 |
           broker and BLE |        |    Host   |
              application |        +-----------+
                          |              |      
                          |              |      
                          |        +-----------+
                          |        |   Home    |
                          +--------|   MQTT    |
                                   |  Broker   |
                                   +-----------+
                                      |      -
                                      |     /|\  
                        MQTT Publish  |      |    
                         application  |      |  MQTT Publish  
                       to peripheral  |      |  peripheral to   
                            messages  |      |  application
                                      |      |  messages
                                     \|/     |    
                                      -      |     
                 +------------+    +-----------+
+------------+   |    BLE     |    |  NAS/BLE  |  
|    BLE     |---| Central#2  |----|  Visited  |   
| Peripheral |   | Controller |    | Central#2 |  
+------------+   |            |    |   Host    |  
                 +------------+    +-----------+  
~~~~~~~~~~
{: #figarch2 title="BLE Message Forwarding Overview"}


RADIUS Profile for BLE {#profile}
==================

User-Name
--------------

Contains a 6 character ASCII upper-case string corresponding to the
hexadecimal encoding of the 22-bit prand value derived from the Bluetooth Resolvable Private Address,
where the first string character represents the most significant
hexadecimal digit, i.e., a prand value of 0x035fb2 is encoded as "035FB2".



NAS-IP-Address, NAS-IPv6-Address
--------------

The NAS-IP-Address contains the IPv4 address of the BLE Central
Host acting as an Authenticator,
and the NAS-IPv6-Address contains the IPv6 address.

NAS-Port
--------------

For use with BLE the NAS-Port will contain the port number of
the BLE Central Host, if this is available.

Service-Type
--------------

For use with BLE, the Service-Type of Authenticate Only (8) is used.


State, Class, Proxy-State
--------------

These attributes are used for the same purposes as described in
{{RFC2865}}.

Vendor-Specific
--------------

Vendor-specific attributes are used for the same purposes as
described in {{RFC2865}}.

Session-Timeout
--------------

When sent along in an Access-Accept without a Termination-Action
attribute or with a Termination-Action attribute set to Default, the
Session-Timeout attribute specifies the maximum number of seconds of
service provided prior to session termination.

Idle-Timeout
--------------

The Idle-Timeout
attribute indicates the maximum time that the BLE wireless device may
remain idle.

Termination-Action
--------------

This attribute indicates what action should be taken when the service
is completed. The value Default (0) indicates that the session should terminate.


Called-Station-Id
--------------

This attribute is used to store the
public Identity Address (BD_ADDR) of the Bluetooth Access Point in ASCII
formatted as specified in {{RFC3580}}.


NAS-Identifier
--------------

This attribute contains a string identifying the BLE Central Host
originating the Access-Request.


NAS-Port-Type {#NPT}
--------------

TBA1:  "Wireless - Bluetooth Low Energy"


Hashed-Password {#hashedpassword}
--------------

Description

The Hashed-Password (TBA2) Attribute allows a RADIUS
client to include a key and hashed password.

Type

>> TBA2

Length

>> Variable

Data Type

>> TLV

Value

>  The TLV data type is specified in {{RFC6929}} and its value
is determined by the TLV-Type field.
Two TLV-Types are defined for use with the Hashed-Password Attribute.


### Hashed-Password.Hmac-Sha256-128-Key

TLV-Type

>> 0 (Hashed-Password.Hmac-Sha256-128-Key)

TLV-Value:

>  A "string" data type encoding binary data representing a random 256-bit key. The
value SHOULD satisfy the requirements of {{RFC4086}}. A new key value MUST be used
whenever the value of Hashed-Password.Hmac-Sha256-128-Password is changed. The key MUST NOT be changed
when a message is being retransmitted.

TLV-Length:

>> 32 octets

### Hashed-Password.Hmac-Sha256-128-Password

TLV-Type

>> 1 (Hashed-Password.Hmac-Sha256-128-Password)

TLV-Value:

>  A "string" data type encoding binary data representing the 128-bit truncated output
of the HMAC-SHA-256-128 algorithm {{RFC4868}} where the input data
corresponds to the 24-bit hash recovered from the Bluetooth Resolvable Private Address
and the key corresponds to the value of the TLV-Type Hashed-Password.Hmac-Sha256-128-Key.

TLV-Length:

>> 16 octets

### Hashed-Password TLV-Type Usage

Two instances of the Hashed-Password Attribute MUST be included in
an Access-Request packet. One instance MUST correspond to the TLV-Type 0
(Hashed-Password.Hmac-Sha256-128-Key) and
one instance MUST correspond to the TLV-Type 1 (Hashed-Password.Hmac-Sha256-128-Password).


GATT-Service-Profile {#GSP}
--------------

Description

The GATT-Service-Profile (TBA3) Attribute allows a RADIUS
client to include one or more GATT Service Profiles which are advertised
by the BLE Peripheral.

Zero or more GATT-Service-Profile Attributes MAY be included in
an Access-Request packet.


Type

>> TBA3

Length

>> 6 octet

Data Type

>> Integer

Value

>  The field is 4 octets, containing a 32-bit unsigned integer that
represents a GATT Service Profile.

##  BLE-Keying-Material Attribute {#BPKM}

Description

The BLE-Keying-Material (TBA3) Attribute allows the transfer of
Identity Address(es) and cryptographic keying material from a RADIUS
Server to the BLE Visited Central Host.

Type

>> TBA3

Length

>> Variable

Data Type

>> TLV

Value

>  The TLV data type is specified in {{RFC6929}} and its value is
determined by the TLV-Type field. Five TLV-Types are defined
for use with the BLE-Keying-Material Attribute.

### BLE-Keying-Material.Peripheral-IA

TLV-Type

>> 0 (BLE-Keying-Material.Peripheral-IA)

TLV-Value:

>  A "string" data type encoding binary data representing
the Peripheral's 6-octet Identity Address.

TLV-Length:

>  6 octets

### BLE-Keying-Material.Central-IA

TLV-Type

>> 1 (BLE-Keying-Material.Central-IA)

TLV-Value:

>  A "string" data type encoding binary data representing
the Central's 6-octet Identity Address.

TLV-Length:

>  6 octets

### BLE-Keying-Material.IV

TLV-Type

>> 2 (BLE-Keying-Material.IV)

TLV-Value:

>  A "string" data type encoding binary data representing
an 8-octet initialization vector. The value MUST be as
specified in {{RFC3394}}.

TLV-Length:

>  8 octets

### BLE-Keying-Material.KEK-ID

TLV-Type

>> 3 (BLE-Keying-Material.KEK-ID)

TLV-Value:

>   A "string" data type encoding binary data representing
the identity of a Key Encryption Key (KEK).
The combination of the BLE-Keying-Material.KEK-ID value
and the RADIUS client and server IP addresses together
uniquely identify a key shared between the RADIUS client and
server.  As a result, the BLE-Keying-Material.KEK-ID need
not be globally unique.  The BLE-Keying-Material.KEK-ID
MUST refer to an encryption key for use with the AES Key
Wrap with 128-bit KEK algorithm {{RFC3394}}.  
This key is used to protect the contents of the BLE-Keying-Material.KM-Data TLV
(see {{KMdataltv}}).

>   The BLE-Keying-Material.KEK-ID is a constant that is configured through an out-of-band
mechanism.  The same value is configured on both the RADIUS client
and server.  If no BLE-Keying-Material.KEK-ID is configured, then the field is set to
0.  If only a single KEK is configured for use between a given
RADIUS client and server, then 0 can be used as the default value.

TLV-Length:

>  16 octets

### BLE-Keying-Material.KM-Type

TLV-Type:

>> 4 (BLE-Keying-Material.KM-Type)

TLV-Value:

>  An "integer" data type
identifying the type of keying material included in the BLE-Keying-Material.KM-Data TLV.  
This allows for multiple keys for different purposes to be present in
the same attribute.  This document defines three values for the
The BLE-Keying-Material.KM-Type

>>>    0 &nbsp; &nbsp; The BLE-Keying-Material.KM-Data TLV contains the
      16-octet Peripheral Identity Resolving Key encrypted using the AES key wrapping process
      with 128-bit KEK defined in {{RFC3394}}

>>>    1  &nbsp; &nbsp; The BLE-Keying-Material.KM-Data TLV contains the encrypted
        16-octet Peripheral Identity Resolving Key
        and the 16-octet Long Term Key generated during an LE Secure Connection bonding procedure.
        The Peripheral IRK is passed as input P1 and P2 and the Long Term Key is passed as input P3 and P4
        in the AES key wrapping process with 128-bit KEK defined in {{RFC3394}}.

>>>    2 &nbsp; &nbsp;  The BLE-Keying-Material.KM-Data TLV contains the 16-octet Peripheral Identity Resolving Key,
        the 16-octet Long Term Key generated during an LE Secure Connection bonding procedure and the
        16-octet Central Identity Resolving Key. The Peripheral IRK is passed as input P1 and P2,
        the Long Term Key is passed as input P3 and P4 and the Central IRK is passed as input P5 and P6
        in the AES key wrapping process with 128-bit KEK defined in {{RFC3394}}.

TLV-Length:

>  4 octets

### BLE-Keying-Material.KM-Data {#KMdataltv}

TLV-Type:

>> 5 (BLE-Keying-Material.KM-Data)

TLV-Value:

>  A "string" data type encoding binary data representing
the actual encrypted keying material as identified using the
BLE-Keying-Material.KM-Type.

TLV-Length:

>  Variable

### BLE-Keying-Material TLV-Type Usage

At least four instances of the BLE-Keying-Material Attribute MUST be included in
an Access-Accept packet, that include the following TLV-Types:

* TLV-Type 0 (BLE-Keying-Material.Peripheral-IA)
* TLV-Type 2 (BLE-Keying-Material.IV)
* TLV-Type 4 (BLE-Keying-Material.KM-Type)
* TLV-Type 5 (BLE-Keying-Material.KM-Data)

If a KEK is configured, then in addition the Access-Accept
packet MUST include the BLE-Keying-Material Attribute with an instance of
TLV-Type 3 (BLE-Keying-Material.KEK-ID). When not present, the NAS MUST
use a default value of 0 for the KEK-ID.

If the BLE Peripheral is connectable and the RADIUS Server authorizes connections,
then in addition the Access-Accept message MUST include the
BLE-Keying-Material Attribute with an instance of
TLV-Type 1 (BLE-Keying-Material.Central-IA).




Forwarding Bluetooth Messages
--------------
RADIUS attributes described in this section are used to exchange information to allow non-IP Bluetooth messages to be
transferred between the BLE Visited Central Host and a Home MQTT Broker.


### MQTT-Broker-URI {#MBU}

Description

The MQTT-Broker-URI (TBA5) Attribute allows a RADIUS
server to specify the URI of the MQTT Broker.
A single MQTT-Broker-URI Attributes MAY be included in
an Access-Accept packet.

If the RADIUS server operates with NAS/BLE Visited Hosts
that are deployed behind firewalls or NAT gateways,
MQTT Messages SHOULD be transported using WebSocket
{{RFC6455}} as a network transport as defined in MQTT {{MQTT}} and the
the attribute SHOULD specify the URI of a WebSocket server
that supports the 'mqtt' Sec-WebSocket-Protocol.

Type

>> TBA5

Length

>> \>=3 octet

Data Type

>> String

Value

>  The String field encodes a URI where the
MQTT service can be accessed, e.g., "wss://broker.example.com:443".

### MQTT-Token {#MT}

Description

The MQTT-Token (TBA6) Attribute allows a RADIUS server
to signal a token for use by an MQTT client in an MQTT CONNECT packet {{MQTT}}.
The token can be used by an MQTT Broker to associate an MQTT Connection from an
MQTT Client with a Network Access Server.

A MQTT-Token Attributes MAY be included in
an Access-Accept packet.

Type

>> TBA6

Length

>> \>=3 octet

Data Type

>> String

Value

>  The String field is contains a token for use
with an MQTT CONNECT packet.


RADIUS Accounting Attributes
--------------

With a few exceptions, the RADIUS accounting attributes defined in
{{RFC2866}} have the same meaning within BLE sessions as they do in dialup sessions and therefore no
additional commentary is needed.

### Acct-Input-Octets and Acct-Output-Octets

These attributes are not not used by BLE Authenticators.

### Acct-Input-Packets

This attribute is used to indicate how many MQTT messages that include the Peripheral Identity Address signalled in  
the BLE-Keying-Material attribute have been sent by the BLE Central Host.

### Acct-Output-Packets

This attribute is used to indicate how many MQTT messages that include the Peripheral Identity Address signalled in  
the BLE-Keying-Material attribute have been received by the BLE Central Host.


### Acct-Terminate-Cause

This attribute indicates how the session was terminated, as described
in {{RFC2866}}. When the idle-timeout attribute is used by the NAS/BLE Visited Host to
terminate a RADIUS Accounting session, it MUST set the Acct-Terminate-Cause set to Lost Carrier (2).


BLE RADIUS Exchange {#ops}
==================

The BLE Peripheral uses
techniques defined in Bluetooth Core Specifications {{BLUETOOTH}} to
establish a bonded, secure, trusted relationship with a BLE
Home Central device in the network. The bonding procedure generates session specific keying material.
The BLE Peripheral sends low duty cycle
advertising events.

The BLE Peripheral moves into coverage of a second BLE Central device that is integrated with a NAS.

The BLE Peripheral sends Advertisements using its Resolvable Public Address.
The contents of the Advertisements are signalled to a BLE Visited Central Host associated with the
second BLE Central device. The received Advertisements sent by the
BLE Peripheral are used by the
BLE Visited Central Host to decide whether to trigger a RADIUS exchange,  e.g., using the presence
and/or contents of specific Advertising Elements.

The NAS associated with the BLE Visited Central Host is configured with the identity of the RADIUS server.
The NAS/BLE Visited Host MAY be statically configured with the identity of a RADIUS Server. Alternatively,
the NAS/BLE Visited Host MAY use the contents of an Advertisement Element received from the BLE Peripheral
to derive an FQDN of the RADIUS sever and use RFC 7585 {{RFC7585}} to dynamically resolve the address of the RADIUS
server. For example, the peripheral can use the Bluetooth URI data type Advertisement Element (0x24) to encode
the Bluetooth defined 'empty scheme' name tag together with a hostname that
identifies the network which operates the BLE Home Central Host associated with the peripheral.
Alternatively, a federation of operators of BLE Visited Centrals and
RADIUS Servers can define the use of the Bluetooth defined Manufacturer Specific Advertisement Data Element (0xFF) together with
a Company Identifier that identifies the federation to signal a federation defined sub-type that encodes information that
enables the BLE Visited Central Host to derive an FQDN of the RADIUS sever associated with the advertising peripheral.

The NAS/BLE Host generates a RADIUS Access-Request message using the prand
from the RPA as the User-Name attribute and the hash from the RPA to generate the
TLV-Type "Hashed-Password.Hmac-Sha256-128-Password".
The NAS-Port-Type is set to "Wireless - Bluetooth Low Energy".

On receiving the RADIUS Access-Request message, the RADIUS Server uses the keying material exposed by the
BLE Home Central Host and attempts to resolve the
User-Name and the TLV-Type "Hashed-Password.Hmac-Sha256-128-Password" to a known BLE Identity Address (IA).  If the RADIUS Server cannot resolve the User-Name
and TLV-Type "Hashed-Password.Hmac-Sha256-128-Password" to a known BLE
Identity Address, the RADIUS server MUST reject the Access-Request.

If the RADIUS Server resolves the User-Name and TLV-Type "Hashed-Password.Hmac-Sha256-128-Password" to a known BLE Identity Address, and the BLE Identity Address is authorized to access via the BLE Visited Host, the RADIUS server recovers the session specific keying material exposed by the
BLE Home Central Host.

(Editor's note - update if/when ncoding switched to TLV)
If the BLE Peripheral is not connectable or connections are not authorized, the RADIUS server encodes the Peripheral Identity Address and the Peripheral Identity Resolving Key in the BLE-Keying-Material attribute and sets the KM Type to 0.
If the BLE Peripheral is connectable and connections are authorized via the BLE Visited Host, the RADIUS server
additionally includes the Central Identity Address and the Long Term Key in the BLE-Keying-Material attribute and sets the KM Type to 1. Finally, if the BLE Peripheral is connectable and connections are authorized via the BLE Visited Host and the security database indicates that the BLE Home Central Host operates using Bluetooth privacy,
then the RADIUS server additionally includes the Central Identity Resolving Key in the BLE-Keying-Material attribute and sets the KM Type to 2.

The RADIUS Server SHOULD include the MQTT-Broker-URI attribute and MAY include the MQTT-Token attribute
by which an MQTT client associated with the BLE Visited Host can establish an MQTT connection with a Home MQTT Broker
for forwarding messages received to/from the BLE peripheral.

On receiving the Access-Accept, the NAS/BLE Visited Host recovers the keying material, including
the BLE Peripheral's Identity Address and then establishes an MQTT Connection with the Home MQTT Broker.
The NAS/BLE Visited Host SHOULD include its NAS-Id in the User Name field of the MQTT CONNECT message
and MAY include an Operator Name, if for example the NAS has been configured with the operator-name attribute (#126) as
specified in RFC5580 {{RFC5580}}.

If the advertisement that triggered the RADIUS exchange corresponds to an ADV_IND then the
NAS/BLE Visited Host can subsequently establish a secure connection with the BLE Peripheral.

~~~~~~~~~~
                   NAS/BLE                                                                                                                
                   Visited                   Home            Home       
   BLE            Central#2                 RADIUS           MQTT   
Peripheral          Host                    Server          Broker
    |                 |                        |              |  
    |                 |                        |              |
    |--BLE----------->|                        |              |  
    |  Advertisement  |                        |              |
    |                 |                        |              |
    |<--------------->|                        |              |
    |  Active Scan    |--Access-Request------->|              |      
    |                 | User-Name=prand        |              |  
    |                 | Hashed-Password.Hmac-Sha256-128-Password=hash
    |                 | NAS-Port-Type=BLE      |              |  
    |                 | GATT-Service-Profile   |              |
    |                 |                        |              |   
    |                 |<-Access-Accept---------|              |    
    |                 | Idle-Timeout           |              |  
    |                 | BLE-Keying-Material    |              |  
    |                 | MQTT-Broker-URI        |              |  
    |                 | MQTT-Token             |              |
    |                 |                        |              |   
    |                 |--Accounting-Request--->|              |   
    |                 | Acct-Status-Type=Start |              |   
    |                 | Session-Id             |              |   
    |                 |                        |              |  
    |                 |--MQTT CONNECT------------------------>|   
    |                 | User Name=[operator_name:]nas-id      |  
    |                 | Password=MQTT Token    |              |    
    |                 |                        |              |   
    |                 |--MQTT PUBLISH------------------------>|  
    |                 | Advertisement(s)       |              |  
    |                 |                        |              |  
   +-----------------------------------------------------------+
   |         Further MQTT and associated BLE Exchanges         |    
   +-----------------------------------------------------------+  
    |                 |                        |              |  
    |--BLE ---------->|--+ Resolve to          |              |  
    |  Advertisement  |  | same Identity       |              |
    |                 |<-+ Address             |              |  
    |              +--|                        |              |  
    |              |  |                        |              |   
    |              +->|Idle Timer Expiry       |              |  
    |                 |                        |              |     
    |                 |--Accounting-Request--->|              |
    |                 | Acct-Status-Type=Stop  |              |    
    |                 | Session-Id             |              |  

~~~~~~~~~~
{: #figops title="BLE RADIUS Exchange"}



Table of Attributes {#Attributes}
==================

The following table provides a guide to which of the attribute defined
may be found in which kinds of packets, and in what quantity.

| Request | Accept | Reject | Challenge| Acct-Request| \#  | Attribute |
| 1+   | 0     | 0    | 0 | 0  | TBA2 | Hashed-Password |
| 0+   | 0     | 0    | 0 | 0  | TBA3 | GATT-Service-Profile |
| 0   | 1+     | 0    | 0 | 0  | TBA4 | BLE-Keying-Material|
| 0   | 0-1     | 0    | 0 | 0  | TBA5 | MQTT-Broker-URI |
| 0   | 0-1     | 0    | 0 | 0  | TBA6 | MQTT-Token |
{: title="Table of Attributes"}

The following table defines the meaning of the above table entries.

| Entry | Meaning |
|0    | This attribute MUST NOT be present in packet.|
|0+   | Zero or more instances of this attribute MAY be present in packet.|
|0-1   |Zero or one instance of this attribute MAY be present in packet.|
|1    | One instance of this attribute MUST be present in packet.|
{: title="Table of Attributes Entry Definition"}


Security Considerations {#Security}
==================

Use of this RADIUS profile for BLE can be between a NAS/BLE Visited Host and a RADIUS Server inside a secure network, or between a NAS/BLE Visited Host and RADIUS server operated in different administrative domains which are connected over the Internet.  All implementations MUST follow {{I-D.draft-dekok-radext-deprecating-radius}}.

The RADIUS profile for BLE devices is designed to operate when BLE devices operate their
physical links with BLE Secure Connections {{BLUETOOTH}}. This approach uses a secure exchange of data over the Bluetooth connection,
together with Elliptic Curve Diffie-Hellman (ECDH) public key cryptography, to
create the session specific symmetric Long Term Key (LTK) which is then exchanged using the BLE-Keying-Material attribute in the RADIUS Access-Accept message.

Bluetooth {{BLUETOOTH}} specifies how an IRK can be generated from an Identity Root (IR) key. Removing the Bluetooth bond in a device will typically trigger the generation of a new IRK key for the device.

The RADIUS profile for BLE devices is designed to operate when BLE devices are configured to operate with Bluetooth Privacy Mode enabled {{BLUETOOTH}}. The BLE device defines the policy of how often it should generate a new Resolvable Private Address. This can be configured to be between every second and every hour, with a default value of every 15 minutes {{BLUETOOTH}}.
This mode mitigates risks
associated with a malicious third-party scanning for and collecting Bluetooth addresses over time and using such to build a picture of the movements of BLE devices and, by inference, the human users of those devices.

The Home MQTT broker can observe the Bluetooth messages exchanged with the BLE Peripheral.
The Bluetooth GATT attributes SHOULD be cryptographically protected at the application-layer.
The Home MQTT Broker MUST be configured with access control lists so that a NAS cannot subscribe to
a topic that is intended for another NAS.

The WebSocket connection MUST operate using a WebSocket Secure connection. If the entropy of the MQTT-Token is known to be low, the WebSocket Secure TLS connection SHOULD be secured with certificate-based mutual TLS.


IANA Considerations {#IANA}
==================

This document defines a new value of TBA1 for RADIUS Attribute Type #61 (NAS-Port-Type) defined in https://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-13

| Value  | Description | Reference |
| TBA1|"Wireless - Bluetooth Low Energy"| {{NPT}} |
{: title="New NAS-Port-Type value defined in this document"}

This document defines new RADIUS attributes, (see section {{profile}}), and assigns values of TBA2, TBA3, TBA4, TBA5 and TBA6 from the RADIUS Attribute Type space https://www.iana.org/assignments/radius-types.

| Tag  | Attribute | Reference |
| TBA2 | Hashed-Password |  {{hashedpassword}} |
| TBA3 | GATT-Service-Profile |  {{GSP}} |
| TBA4 | BLE-Keying-Material| {{BPKM}} |
| TBA5 | MQTT-Broker-URI |  {{MBU}} |
| TBA6 | MQTT-Token |  {{MT}} |
{: title="New RADIUS attributes defined in this document"}




--- back



#  MQTT Interworking

This section describes how a NAS/BLE Visited Host supporting the BLE RADIUS profile can interwork with a Home MQTT Message Broker in order to use MQTT topics to deliver Bluetooth messages to/from a BLE Peripheral. It is intended to move this material to another document - but is included here to describe, at a high level, the MQTT interworking established by the RADIUS exchange.

## Establishing a Session to a MQTT-Broker-URI

If the NAS/BLE Visited Host is signalled a MQTT-Broker-URI in an Access-Accept with which it does not have an established MQTT connection, then it MUST establish an MQTT connection. It the NAS/BLE Visited Host is behind a firewall or NAT gateway it MUST use WebSocket transport for the MQTT connection. The user name in the MQTT CONNECT message SHOULD include the NAS-ID and MAY include the name of the operator of the NAS/BLE Visited Host.

~~~~~~~~~~
                   NAS/BLE                                   
                   Visited                   Home            Home       
   BLE             Central#2                 RADIUS          MQTT  
Peripheral           Host                   Server          Broker
    |                 |                        |              |   
    |                 |                        |              |  
    |                 |--Accounting-Request--->|              |  
    |                 | Acct-Status-Type=Start |              |    
    |                 | Session-Id             |              |   
    |                 | Chargeable-User-Id     |              |   
    |                 |                        |              |   
    |                 |--HTTP GET---------------------------->|  
    |                 | Upgrade:websocket      |              |
    |                 | Connection:upgrade     |              |  
    |                 | Sec-WebSocket-Protocol=mqtt           |  
    |                 |                        |              |
    |                 |<-HTTP 101--------------|--------------|  
    |                 | Upgrade:websocket      |              |  
    |                 | Connection:upgrade     |              |  
    |                 | Sec-WebSocket-Protocol=mqtt           |  
    |                 |                        |              |  
    |                 |--MQTT CONNECT------------------------>|   
    |                 | User Name=[operator_name:]nas-id      |  
    |                 | Password=MQTT Token    |              |   
    |                 |                        |              |   
    |                 |<-MQTT CONNACK-------------------------|  
    |                 |                        |              |
    |                 |                        |              |        
~~~~~~~~~~
{: #figest title="Establishing an MQTT connection to a Home Broker using WebSocket transport"}

## MQTT topics

The following topic is used by the MQTT client of the BLE Visited Host to signal active and passive scan advertisements received from BLE Peripherals to the home MQTT Broker.

* {peripheral_identity_address}/advertisement/gatt-ind

If the BLE Peripheral is connectable, the MQTT client of the BLE Visited Host SHOULD subscribe
to the following message topics to be able to receive GATT requests from the Home MQTT Broker:

  2. {peripheral_identity_address}/connect/gatt-req : when publishing a message on the {peripheral_identity_address}/connect/gatt-req topic, an MQTT client SHOULD include the following as a response topic
  {peripheral_identity_address}/connect/gatt-res.
  3. {peripheral_identity_address}/disconnect/gatt-req : when publishing a message on the {peripheral_identity_address}/disconnect/gatt-req topic, an MQTT client SHOULD include the following as a response topic
  {peripheral_identity_address}/disconnect/gatt-res.
  4. {peripheral_identity_address}/read/gatt-req : when publishing a message on the {peripheral_identity_address}/read/gatt-req topic, an MQTT client SHOULD include the following as a response topic
  {peripheral_identity_address}/read/gatt-res.
  5. {peripheral_identity_address}/write/gatt-req : when publishing a message on the {peripheral_identity_address}/write/gatt-req topic, an MQTT client SHOULD include the following as a response topic
  {peripheral_identity_address}/write/gatt-res.
  6. {peripheral_identity_address}/service-discovery/gatt-req : when publishing a message on the {peripheral_identity_address}/service-discovery/gatt-req topic, an MQTT client SHOULD include the following as a response topic
  {peripheral_identity_address}/service-discovery/gatt-res.
  7. {peripheral_identity_address}/notification/gatt-ind-res :  when sending indications, the MQTT client of the NAS/BLE Visited Host
  SHOULD publish the message using the topic:{peripheral_identity_address}/notification/gatt-ind-req indication and SHOULD include the following as a response topic {peripheral_identity_address}/notification/gatt-ind-res.


## MQTT Exchange for Non-Connectable BLE Peripherals

If the BLE Peripheral indicates in its scan that it is not connectable, the
NAS/BLE Visited Host is responsible for publishing the received advertisements
received from the authenticated BLE Peripheral.

On idle-timeout the NAS/BLE Visited Host MUST send
an Accounting-Request message with Acct-Status-Type set to STOP and
Acct-Terminate-Cause set to Lost Carrier (2).

~~~~~~~~~~
                   NAS/BLE                                                                                                                
                   Visited                                   Home                                                                                 
   BLE            Central#2                  RADIUS          MQTT                                                                             
Peripheral           Host                    Server         Broker                                                                            
    |                 |                        |              |         
    |--BLE ---------->|                        |              |       
    |  Advertisement  |                        |              |        
  +---------------------+                      |              |   
  | |   Active Scan   | |                      |              |                     
  | |<-BLE SCAN_REQ---| |                      |              |     
  | |                 | |                      |              |       
  | |--BLE SCAN_RSP-->| |                      |              |
  +---------------------+                      |              |                                                                               
    |                 |--MQTT PUBLISH------------------------>|                                                                               
    |                 | topic:{peripheral_identity_address}/  |                                                                               
    |                 | advertisement/gatt-ind |              |                                                                               
    |                 | msg:Advertising Report |              |                                                                               
    |                 |                        |              |                                                                               
    |--BLE ---------->|                        |              |                                                                               
    |  Advertisement  |--MQTT PUBLISH------------------------>|                                                                               
    |              +--| topic:{peripheral_identity_address}/  |                                                                               
    |              |  | advertisement/gatt-ind |              |                                                                               
    |              |  | msg:Advertising Report |              |                                                                               
    |              |  |                        |              |                                                                               
    |              |  |                        |              |                                                                               
    |              |  |                        |              |                                                                               
    |              +->|Idle Timer Expiry       |              |                                                                               
    |                 |                        |              |                                                                               
    |                 |--Accounting-Request--->|              |                                                                               
    |                 | Acct-Status-Type=Stop  |              |                                                                               
    |                 | Session-Id             |              |                                                                               
    |                 |                        |              |                                                                               
    |             +-----------------------------------------------+                                                                           
    |             |      Last Session to MQTT Broker Stopped      |                                                                           
    |             +-----------------------------------------------+                                                                           
    |                 |                                       |                                                                               
    |                 |--MQTT DISCONNECT--------------------->|                                                                               
    |                 |                                       |                                                                               
    |                 |--Close WebSocket--------------------->|                                                                               
    |                 |                                       |     
~~~~~~~~~~
{: #figscan title="MQTT Exchange for Non-Connectable BLE Peripherals"}

## Initial MQTT Exchange for Connectable BLE Peripherals

If the BLE Peripheral indicates in its scan that it is connectable, the
NAS/BLE Visited Host is responsible for publishing the received advertisements
received from the authenticated BLE Peripheral and to subscribing to the GATT requests
published for the BLE Peripheral's Identity Address.

~~~~~~~~~~
                   NAS/BLE                                                                                                               
                   Visited                                    Home                                                                                
   BLE            Central#2                                   MQTT                                                                            
Peripheral           Host                                    Broker                                                                           
    |                 |                                        |                                                                              
    |--BLE----------->|                                        |                                                                              
    |  Advertisement  |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                               
    |                 |  advertisement/gatt-ind                |                                                                               
    |                 |  msg:Advertising Report                |   
    |                 |                                        |   
  +--------------------------------------------------------------+                                                                            
  |                      GATT Subscription                       |                                                                            
  +--------------------------------------------------------------+                                                                            
    |                 |                                        |                                                                              
    |                 |---MQTT SUBSCRIBE---------------------->|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                             
    |                 |  +/gatt-req                            |          
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  +/gatt-ind-res                        |
    |                 |                                        |                                                                              
  +--------------------------------------------------------------+                                                                            
  |           GATT Connection and Service Discovery              |                                                                            
  +--------------------------------------------------------------+                                                                            
    |                 |                                        |                                                                              
    |                 |<--MQTT PUBLISH-------------------------|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |<-BLE PDU------->|  gatt-req/connect                      |                                                                              
    |  Exchange       |  response topic:                       |                                                                              
    |                 |  {peripheral_identity_address}/        |                                                                              
    |                 |  gatt-res/connect                      |                                                                              
    |                 |  correlation data:{binary_data}        |                                                                              
    |                 |  msg:                                  |
    |                 |                                        |                                                                              
    |                 |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  gatt-res/connect                      |                                                                              
    |                 |  correlation data:{binary data}        |                                                                              
    |                 |  msg: connect-id or error              |                                                                              
    |                 |                                        |
    |                 |<--MQTT PUBLISH-------------------------|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |<-BLE PDU------->|  gatt-req/service-discovery            |                                                                              
    |  Exchange       |  response topic:                       |                                                                              
    |                 |  {peripheral_identity_address}/        |                                                                              
    |                 |  gatt-res/service-discovery            |                                                                              
    |                 |  correlation data:{binary_data}        |                                                                              
    |                 |  msg: connect-id, optional UUID        |
    |                 |                                        |                                                                              
    |                 |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  gatt-res/service-discovery            |                                                                              
    |                 |  correlation data:{binary data}        |                                                                              
    |                 |  msg: service UUID or error            |                                                                              
    |                 |                                        |
    |                 |<--MQTT PUBLISH-------------------------|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |<-BLE PDU------->|  disconnect/gatt-req                   |                                                                              
    |  Exchange       |  response topic:                       |                                                                              
    |                 |  {peripheral_identity_address}/        |                                                                              
    |                 |  disconnect/gatt-res                   |                                                                              
    |                 |  correlation data:{binary_data}        |                                                                              
    |                 |  msg: connect-id                       |
    |                 |                                        |                                                                              
    |                 |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  disconnect/gatt-res                   |                                                                              
    |                 |  correlation data:{binary data}        |                                                                              
    |                 |  msg: ok or error                      |                                                                              
    |                 |                                        |   

~~~~~~~~~~
{: #figcon title="MQTT Exchange for GATT Service Discovery"}

## MQTT Exchange for Reading a GATT Attribute

If the BLE Peripheral is connectable, a Bluetooth Application can read GATT attributes.

~~~~~~~~~~
                    NAS/BLE                                                                                                               
                    Visited                                   Home                                                                                
   BLE             Central#2                                  MQTT                                                                            
Peripheral           Host                                    Broker                                                                           
    |                 |                                        |                                                                              
  +--------------------------------------------------------------+                                                                            
  |                      GATT Read Request                       |                                                                            
  +--------------------------------------------------------------+                                                                            
    |                 |                                        |                                                                              
    |                 |<--MQTT PUBLISH-------------------------|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |<-BLE PDU------->|  read/gatt-req                         |                                                                              
    |  Exchange       |  response topic:                       |                                                                              
    |                 |  {peripheral_identity_address}/        |                                                                              
    |                 |  read/gatt-res                         |                                                                              
    |                 |  correlation data:{binary_data}        |                                                                              
    |                 |  msg: Characteristic optional offset,  |
    |                 |       optional maxlen                  |                                                                       
    |                 |                                        |                                                                              
    |                 |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  read/gatt-res                         |                                                                              
    |                 |  correlation data:{binary data}        |                                                                              
    |                 |  msg: Handle, opcode, offset, value or |                                                                              
    |                 |       error                            |    
~~~~~~~~~~
{: #figread title="MQTT Exchange for GATT Read Attribute"}

## MQTT Exchange for Writing a GATT Attribute

If the BLE Peripheral is connectable, a Bluetooth Application can write GATT attributes.


~~~~~~~~~~
                   NAS/BLE                                                                                                               
                   Visited                                    Home                                                                                
   BLE            Central#2                                   MQTT                                                                            
Peripheral           Host                                    Broker                                                                           
    |                 |                                        |                                                                              
  +--------------------------------------------------------------+                                                                            
  |                     GATT Write Request                       |                                                                            
  +--------------------------------------------------------------+                                                                            
    |                 |                                        |                                                                              
    |                 |<--MQTT PUBLISH-------------------------|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                             
    |<-BLE PDU------->|  write/gatt-req                        |                                                                              
    |  Exchange       |  response topic:                       |                                                                              
    |                 |  {peripheral_identity_address}/        |                                                                              
    |                 |  write/gatt-res                        |                                                                              
    |                 |  correlation data:{binary_data}        |                                                                              
    |                 |  msg: characteristic, length, value    |                                                                              
    |                 |                                        |                                                                              
    |                 |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  write/gatt-res                        |                                                                              
    |                 |  correlation data:{binary data}        |                                                                              
    |                 |  msg: success or error                 |                                                                              
    |                 |                                        |    
~~~~~~~~~~
{: #figwrite title="MQTT Exchange for GATT Write Attribute"}

## MQTT Exchange for BLE Peripheral initiated Notifications

A Bluetooth Application can subscribe to receive Bluetooth notifications sent by the BLE Peripheral.


~~~~~~~~~~
                    NAS/BLE                                                                                                               
                    Visited                                   Home                                                                                
   BLE             Central#2                                  MQTT                                                                            
Peripheral           Host                                    Broker                                                                           
    |                 |                                        |                                                                              
  +--------------------------------------------------------------+                                                                            
  |                GATT Set Notification Request                 |                                                                            
  +--------------------------------------------------------------+                                                                            
    |                 |                                        |                                                                              
    |                 |<--MQTT PUBLISH-------------------------|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                             
    |<-BLE PDU------->|  write/gatt-req                        |                                                                              
    |  Exchange       |  response topic:                       |                                                                              
    |                 |  {peripheral_identity_address}/        |                                                                              
    |                 |  write/gatt-res                        |                                                                              
    |                 |  correlation data:{binary_data}        |                                                                              
    |                 |  msg: characteristic, enable/disable   |                                                                              
    |                 |                                        |                                                                              
    |                 |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  write/gatt-res                        |                                                                              
    |                 |  correlation data:{binary data}        |                                                                              
    |                 |  msg: success or error                 |                                                                              
    |                 |                                        |   
  +--------------------------------------------------------------+                                                                            
  |                      GATT Notification                       |                                                                            
  +--------------------------------------------------------------+   
    |                 |                                        |                                                                              
    |--BLE ---------->|                                        |                                                                              
    |  Notification   |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  notification/gatt-ind                 |                                                                              
    |                 |  msg:handle & value                    |   
    |                 |                                        |   
~~~~~~~~~~
{: #fignotification title="MQTT Exchange for BLE Peripheral Notifications"}

## MQTT Exchange for BLE Peripheral initiated Indications

A Bluetooth Application can subscribe to receive Bluetooth indications sent by the BLE Peripheral.


~~~~~~~~~~
                    NAS/BLE                                                                                                               
                    Visited                                   Home                                                                                
   BLE             Central#2                                  MQTT                                                                            
Peripheral           Host                                    Broker                                                                           
    |                 |                                        |                                                                              
  +--------------------------------------------------------------+                                                                            
  |                 GATT Set Indication Request                  |                                                                            
  +--------------------------------------------------------------+                                                                            
    |                 |                                        |                                                                              
    |                 |<--MQTT PUBLISH-------------------------|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                             
    |<-BLE PDU------->|  write/gatt-req                        |                                                                              
    |  Exchange       |  response topic:                       |                                                                              
    |                 |  {peripheral_identity_address}/        |                                                                              
    |                 |  write/gatt-res                        |                                                                              
    |                 |  correlation data:{binary_data}        |                                                                              
    |                 |  msg: identifier & handle              |                                                                              
    |                 |                                        |                                                                              
    |                 |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  write/gatt-res                        |                                                                              
    |                 |  correlation data:{binary data}        |                                                                              
    |                 |  msg: procedure complete               |                                                                              
    |                 |                                        |   
  +--------------------------------------------------------------+                                                                            
  |                       GATT Indication                        |                                                                            
  +--------------------------------------------------------------+   
    |                 |                                        |                                                                              
    |--BLE----------->|                                        |                                                                              
    |  Indication     |---MQTT PUBLISH------------------------>|                                                                              
    |                 |  topic:{peripheral_identity_address}/  |                                                                              
    |                 |  notification/gatt-ind-req             |                                                                              
    |                 |  response topic:                       |
    |                 |  {peripheral_identity_address}/        |   
    |                 |  notification/gatt-ind-res             |                                                                              
    |                 |  correlation data:{binary_data}        |                                                                              
    |                 |  msg: Indication                       |
    |                 |                                        |
    |                 |<--MQTT PUBLISH-------------------------|                                                                              
    |<-BLE------------|  topic:{peripheral_identity_address}/  |                                                                              
    |  Status         |  notification/gatt-ind-res             |                                                                              
    |                 |  correlation data:{binary data}        |                                                                              
    |                 |  msg: Indication confirmation          |   
    |                 |                                        |
~~~~~~~~~~
{: #figindication title="MQTT Exchange for BLE Peripheral Indications"}

## MQTT Exchange for dealing with NAS Mobility

~~~~~~~~~~
              NAS/BLE      NAS/BLE                                                                                                        
              Visited      Visited                            Home                                                                        
   BLE       Central#2    Central#3                           MQTT                                                                        
Peripheral      Host         Host                            Broker                                                                       
    |            |            |                                |                                                                          
  +--------------------------------------------------------------+                                                                        
  |          Initial Authentication With Central#2               |                                                                        
  +--------------------------------------------------------------+                                                                        
    |            |            |                                |                                                                          
    |            |--MQTT SUBSCRIBE --------------------------->|                                                                          
    |            |  topic:{periperal_identity_address}/        |                                                                          
    |            |  +/gatt-req                                 |                                                                          
    |            |            |                                |                                                                          
  +--------------------------------------------------------------+                                                                        
  |   NAS Mobility to Central#3 without MQTT unsubscription      |                                                                        
  +--------------------------------------------------------------+                                                                        
    |            |            |                                |                                                                          
    |            |            |--MQTT SUBSCRIBE--------------> |                                                                          
    |            |            | topic:                         |                                                                          
    |            |            | {peripheral_identity_address}/ |                                                                          
    |            |            | +/gatt-req                     |                                                                          
    |            |            |                                |                                                                          
  +--------------------------------------------------------------+                                                                        
  |     Example GATT Connection Request with NAS Mobility        |                                                                        
  +--------------------------------------------------------------+                                                                        
    |            |            |                                |                                                                          
    |            |<-MQTT PUBLISH-------------------------------|                                                                          
    |         +--| topic:{peripheral_identity_address}/        |                                                                          
    |         |  | connect/gatt-req                            |                                                                          
    |         |  | response topic:                             |                                                                          
    |         |  | {peripheral_identity_address}/              |                                                                          
    |         |  | connect/gatt-res                            |                                                                          
    |         |  | correlation data:{binary_data}              |                                                                          
    |         |  | msg:       |                                |                                                                          
    |         |  |            |                                |                                                                          
    |         |  |            |<--MQTT PUBLISH-----------------|                                                                          
    |         |  |            | topic:                         |                                                                          
    |         |  |            | {peripheral_identity_address}/ |                                                                          
    |         |  |            | connect/gatt-req               |                                                                          
    |<-BLE----|-------------->| response topic:                |                                                                          
    |  PDU    |  |            | {peripheral_identity_address}/ |                                                                          
    |  Exchange  |            | connect/gatt-res               |                                                                          
    |         |  |            | correlation data:{binary_data} |                                                                          
    |         |  |            | msg:                           |                                                                          
    |         |  |            |                                |                                                                          
    |         |  |            |---MQTT PUBLISH---------------->|                                                                          
    |         |  |            | topic:                         |                                                                          
    |         |  |            | {peripheral_identity_address}/ |                                                                          
    |Central#2|  |            | connect/gatt-res               |                                                                          
    |      BLE|  |            | correlation data:{binary data} |                                                                          
    |  Timeout|  |            | msg: connect-id                |                                                                          
    |         +->|            |                                |                                                                          
    |            |---MQTT PUBLISH----------------------------->|                                                                          
    |            | topic:{peripheral_identity_address}/        |                                                                          
    |            | connect/gatt-res                            |                                                                          
    |            | correlation data:{binary data}              |                                                                          
    |            | msg: procedure timeout                      |                                                                          
    |            |            |                                |                                                                          
  +--------------------------------------------------------------+                                                                        
  |       MQTT Broker drops timeout message for PUBLISH          |                                                                        
  |              with duplicated correlation data                |                                                                        
  +--------------------------------------------------------------+                                                                        
~~~~~~~~~~
{: #figmobility title="MQTT Exchange for Inter-NAS Mobility without MQTT Unsubscription"}

## MQTT Exchange for ending a session for a connected BLE Peripheral

On idle-timeout the NAS/BLE Visited Host MUST un-subscribe from any subscribed to topics and send
an Accounting-Request message with Acct-Status-Type set to STOP and Acct-Terminate-Cause set to Lost Carrier (2).

~~~~~~~~~~
                    NAS/BLE                                                                                                             
                    Visited                   Home            Home                                                                              
   BLE             Central#2                 RADIUS           MQTT                                                                          
Peripheral           Host                    Server          Broker                                                                         
    |                 |                         |              |                                                                            
    |--BLE----------->|                         |              |                                                                            
    |  Advertisement  |---MQTT PUBLISH------------------------>|                                                                            
    |              +--|  topic:{peripheral_identity_address}/  |                                                                            
    |              |  |  advertisement/gatt-ind |              |                                                                            
    |              |  |  msg:Advertising Report |              |                                                                            
    |              |  |                         |              |                                                                            
    |              |  |                         |              |                                                                            
    |              +->|Idle Timer Expiry        |              |                                                                            
    |                 |                         |              |                                                                            
    |                 |---Accounting-Request--->|              |                                                                            
    |                 |  Acct-Status-Type=Stop  |              |                                                                            
    |                 |                         |              |                                                                            
    |                 |---MQTT UNSUBSCRIBE-------------------->|                                                                            
    |                 |  topic:{peripheral_identity_address}/  |                                                                           
    |                 |  +/gatt-req             |              |                                                                            
    |                 |  topic:{peripheral_identity_address}/  |                                                                            
    |                 |  +/gatt-ind-res         |              |  
    |                 |                         |              |                                                                            
    |             +------------------------------------------------+                                                                        
    |             |       Last Session to MQTT Broker Stopped      |                                                                        
    |             +------------------------------------------------+                                                                        
    |                 |                         |              |                                                                            
    |                 |---MQTT DISCONNECT--------------------->|                                                                            
    |                 |                         |              |                                                                            
    |                 |---Close WebSocket--------------------->|                                                                            
    |                 |                         |              |               
~~~~~~~~~~
{: #figdisc title="MQTT Exchange when disconnecting from a connected BLE Peripheral"}

#  History of Changes

Note: This appendix will be deleted in the final version of the document.

From version 00 -> 01:

* switched from User-Password to new Hashed-Password attribute using SHA256

* switched to TLV-encoding of BLE-Keying-Material

* re-ordered MQTT topic definitions

* removed redundant attribute sections

# Acknowledgements {#Acknowledgements}
{: numbered="false"}

Thanks to Oleg Pekar and Eric Vyncke for their review comments.
