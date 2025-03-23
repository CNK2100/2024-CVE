# VULNERABILTIES SUMMARY DESCRIPTION
This is a public reference that contains the minimum require information for the vulnerability covered by CVE-2024-50920, CVE-2024-50921, CVE-2024-50924, CVE-2024-50928, CVE-2024-50929, CVE-2024-50930, CVE-2024-50931.

The details for each CVE-2024-***** are provided at the end of this document.


### Vulnerability description

Denial of Service (DoS) vulnerabilities in Z-Wave chipsets. These vulnerabilities may allow a remote, unauthenticated attacker to inject malicious packets to the Z-Wave controller to cause DoS.

### CVSS Severity: High

### Discoverer

Thanks to Carlos Kayembe Nkuba, Jimin Kang, Professor Seunghoon Woo, and Professor Heejo Lee from Korea University for reporting these vulnerabilities.

### Additional Information

With the use of tools and transceivers that can decode Z-Wave frame( e.g., Scapy-radio with HackRF One;
Yard Stick One; RFCat ; RTL-SDR; Zniffer with Sigma UZB) an attacker sniffs and captures any Z-Wave 
communication of a target Z-Wave smart home. 
Then he retrieves the Z-Wave HomeID and NodeID of devices that are transmiting packets in the network. 
With the knowledge of the HomeID, the attacker can brute force the Z-Wave network to know all remaining 
available smart devices in the network. This is achieved by sending to all possible Z-Wave node (2 to 232) 
either these Z-Wave frames: No Operation (NOP), SWITCH_BINARY_GET, or Node Information (NIF), SECURITY_NONCE_GET, 
SECURITY_2_NONCE_GET  to get the acknowledgement (ACK) from devices. 

From this ACK the attacker retrieves the node ID of devices that responded and their capabilities. 

With the knowledge of the Z-Wave HomeID and NodeID of the device, the attacker crafts a malicious packet with a desired malicious payload and sends it to the target Z-Wave device by using a customized Z-Wave packet management software and hardware such as  HackRF One,  Yard Stick One,  RFCat, or CC1110. 

The controller will accept and validate the malicious packet, which cause a DoS. These attacks are critical because they render the Z-Wave controller vulnerable to DoS attacks, which make their service inaccessible to authentic smart home users. 

### How does an attacker exploit this vulnerability?

Attacker and target device need to be within a range of 40 to 100 meters. 
The range can be increased by using an advanced Software-Defined Radio (SDR) hardware.

### What is the impact of this vulnerability?

Denial of service (DoS) on Z-Wave controller.

### Vendor of Product

Silicon Labs ( SiLabs)


### Affected Product Code Base

Z Wave controllers with Silicon Labs Chipset
 
### Attack Type

Proximate remote attack

### Impact Denial of Service

Denial of Service on the controller.


### Attack Vectors

By crafting a malicious Z-Wave packet and sending it to the Z-Wave controller and devices.  

### Vendor contact timeline

2023-11-12: Contacting US. CERT/CC

2023-11-13: CERT/CC added 17 vendors to the case

2024-02-15: Silicon Labs (SiLabs) published a Security Advisory A-00000502

It can be accessible after creating a free account at: https://community.silabs.com/s/alert/a45Vm00000000knIAA/a00000502

2024-02-29 : Silicon Labs (SiLabs) published a second Security Advisory A-00000505

It can be accessible after creating a free account at: https://community.silabs.com/s/contentdocument/069Vm000002020u


### Fix/Workaround Method

Check SiLabs Security Advisory A-00000502

It can be accessible after creating a free account at: https://community.silabs.com/s/alert/a45Vm00000000knIAA/a00000502

Check SiLabs Security Advisory A-00000505

It can be accessible after creating a free account at: https://community.silabs.com/s/contentdocument/069Vm000002020u

### Reference

- https://ccs.korea.ac.kr/pds/Vulnerabilities_in_ZWave.html
- https://github.com/CNK2100/2024-CVE/blob/main/README.md
- Create a free account at https://community.silabs.com to access the response document from the affected vendor, Silicon Labs (SiLabs).
- https://community.silabs.com/068Vm00000211lw
- https://community.silabs.com/s/contentdocument/069Vm000001Gv50
- Experiment videos can be accessed at below two links:
- https://drive.google.com/file/d/1LBycOFbQThFxuGedefVfNqNa0TbTE0R0/view
- https://drive.google.com/file/d/1aZMcGRUVtweYkWlcHzWRsl1jhp1nSBYs/view
  
------------------------------------------

# INDIVIDUAL CVE DESCRIPTION


## 1. CVE-2024-50920


### Suggested description
Insecure permissions in Silicon Labs (SiLabs) Z-Wave Series 700 and 800 v7.21.1 allow attackers to create a fake node via supplying crafted packets.

### Vulnerability Type
Insecure Permissions

### Vendor of Product
Silicon Labs (SiLabs)

### Affected Product Code Base
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier - Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier

### Affected Component
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier

### Attack Type
Remote

### Impact Code execution
true

### Impact Denial of Service
true

### Impact Escalation of Privileges
true

### Attack Vectors

Malformed packets can be sent to add a new fake node in controller memory.

### Reference

- https://ccs.korea.ac.kr/pds/Vulnerabilities_in_ZWave.html
- https://github.com/CNK2100/2024-CVE/blob/main/README.md
- Create a free account at https://community.silabs.com to access the response document from the affected vendor, Silicon Labs (SiLabs).
- https://community.silabs.com/068Vm00000211lw
- https://community.silabs.com/s/contentdocument/069Vm000001Gv50
- Experiment videos can be accessed at below two links:
- https://drive.google.com/file/d/1LBycOFbQThFxuGedefVfNqNa0TbTE0R0/view
- https://drive.google.com/file/d/1aZMcGRUVtweYkWlcHzWRsl1jhp1nSBYs/view

### Has vendor confirmed or acknowledged the vulnerability?

true

### Discoverer

Thanks to Carlos Kayembe Nkuba, Jimin Kang, Professor Seunghoon Woo, and Professor Heejo Lee from Korea University for reporting these vulnerabilities.




## 2. CVE-2024-50921

### Suggested description
Insecure permissions in Silicon Labs (SiLabs) Z-Wave Series 700 and 800 v7.21.1 allow attackers to cause a Denial of Service (DoS) via repeatedly sending crafted packets to the controller.
   
  
   
### Vulnerability Type 
Insecure Permissions
   
  
   
### Vendor of Product 
Silicon Labs (SiLabs)
   
  
   
### Affected Product Code Base 
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier - Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier
   
  
   
### Affected Component 
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier
   
  
   
### Attack Type 
Remote
   
  
   
### Impact Code execution 
true
   
  
   
### Impact Denial of Service 
true
   
  
   
### Impact Escalation of Privileges 
true
   
  
   
### Attack Vectors 
Malformed packets can be sent to keep the controller busy with responding, which denies service to any other tasks that may be occuring. This denial of service can be used to repeatedly jam the controller.
   
  
   
   

### Reference

- https://ccs.korea.ac.kr/pds/Vulnerabilities_in_ZWave.html
- https://github.com/CNK2100/2024-CVE/blob/main/README.md
- Create a free account at https://community.silabs.com to access the response document from the affected vendor, Silicon Labs (SiLabs).
- https://community.silabs.com/068Vm00000211lw
- https://community.silabs.com/s/contentdocument/069Vm000001Gv50
- Experiment videos can be accessed at below two links:
- https://drive.google.com/file/d/1LBycOFbQThFxuGedefVfNqNa0TbTE0R0/view
- https://drive.google.com/file/d/1aZMcGRUVtweYkWlcHzWRsl1jhp1nSBYs/view

### Has vendor confirmed or acknowledged the vulnerability?

true

### Discoverer

Thanks to Carlos Kayembe Nkuba, Jimin Kang, Professor Seunghoon Woo, and Professor Heejo Lee from Korea University for reporting these vulnerabilities.







## 3. CVE-2024-50924

### Suggested description 
Insecure permissions in Silicon Labs (SiLabs) Z-Wave Series 700 and 800
v7.21.1 allow attackers to cause disrupt communications between the
controller and the device itself via repeatedly sending crafted packets
to the controller.
   
  
   
### Vulnerability Type 
Insecure Permissions
   
  
   
### Vendor of Product 
Silicon Labs ( SiLabs)
   
  
   
### Affected Product Code Base 
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier - Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier
   
  
   
### Affected Component 
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier
   
  
   
### Attack Type 
Remote
   
  
   
### Impact Code execution 
true
   
  
   
### Impact Denial of Service 
true
   
  
   
### Impact Escalation of Privileges 
true
   
  
   
### Attack Vectors 
Malformed packets can be sent to the controller, preventing communication with the end device.
   
  
   
   


### Reference

- https://ccs.korea.ac.kr/pds/Vulnerabilities_in_ZWave.html
- https://github.com/CNK2100/2024-CVE/blob/main/README.md
- Create a free account at https://community.silabs.com to access the response document from the affected vendor, Silicon Labs (SiLabs).
- https://community.silabs.com/068Vm00000211lw
- https://community.silabs.com/s/contentdocument/069Vm000001Gv50
- Experiment videos can be accessed at below two links:
- https://drive.google.com/file/d/1LBycOFbQThFxuGedefVfNqNa0TbTE0R0/view
- https://drive.google.com/file/d/1aZMcGRUVtweYkWlcHzWRsl1jhp1nSBYs/view

### Has vendor confirmed or acknowledged the vulnerability?

true

### Discoverer

Thanks to Carlos Kayembe Nkuba, Jimin Kang, Professor Seunghoon Woo, and Professor Heejo Lee from Korea University for reporting these vulnerabilities.




## 4. CVE-2024-50928

### Suggested description 
Insecure permissions in Silicon Labs (SiLabs) Z-Wave Series 700 and 800
v7.21.1 allow attackers to change the wakeup interval of end devices in
controller memory, disrupting the device's communications with the
controller.
   
  
   
### Vulnerability Type 
Insecure Permissions
   
  
   
### Vendor of Product 
Silicon Labs
   
  
   
### Affected Product Code Base 
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier - Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier
   
  
   
### Attack Type 
Remote
   
  
   
### Impact Code execution 
true
   
  
   
### Impact Denial of Service 
true
   
  
   
### Impact Escalation of Privileges 
true
   
  
   
### Attack Vectors 
Malformed packets can be sent to change the wakeup interval of end devices in controller memory, preventing the controller's periodic communication with the end device. The end device behavior is not impacted by this change.
   
  
   
   

### Reference

- https://ccs.korea.ac.kr/pds/Vulnerabilities_in_ZWave.html
- https://github.com/CNK2100/2024-CVE/blob/main/README.md
- Create a free account at https://community.silabs.com to access the response document from the affected vendor, Silicon Labs (SiLabs).
- https://community.silabs.com/068Vm00000211lw
- https://community.silabs.com/s/contentdocument/069Vm000001Gv50
- Experiment videos can be accessed at below two links:
- https://drive.google.com/file/d/1LBycOFbQThFxuGedefVfNqNa0TbTE0R0/view
- https://drive.google.com/file/d/1aZMcGRUVtweYkWlcHzWRsl1jhp1nSBYs/view

### Has vendor confirmed or acknowledged the vulnerability?

true

### Discoverer

Thanks to Carlos Kayembe Nkuba, Jimin Kang, Professor Seunghoon Woo, and Professor Heejo Lee from Korea University for reporting these vulnerabilities.







## 5. CVE-2024-50929

### Suggested description 
Insecure permissions in Silicon Labs (SiLabs) Z-Wave Series 700 and 800
v7.21.1 allow attackers to arbitrarily change the device type in the
controller's memory, leading to a Denial of Service (DoS).
   
  
   
### Vulnerability Type 
Insecure Permissions
   
  
   
### Vendor of Product 
Silicon Labs (SiLabs)
   
  
   
### Affected Product Code Base 
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier - Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier
   
  
   
### Affected Component 
Z-Wave Series 700 and 800 devices using Silicon Labs Z-Wave SDK v7.21.1 and earlier
   
  
   
### Attack Type 
Remote
   
  
   
### Impact Code execution 
true
   
  
   
### Impact Denial of Service 
true
   
  
   
### Impact Escalation of Privileges 
true
   
  
   
### Attack Vectors 
Malformed packets can be sent to change the device type in controller memory, preventing communication with the end device even though it remains in the network.
   
  
   
   


### Reference

- https://ccs.korea.ac.kr/pds/Vulnerabilities_in_ZWave.html
- https://github.com/CNK2100/2024-CVE/blob/main/README.md
- Create a free account at https://community.silabs.com to access the response document from the affected vendor, Silicon Labs (SiLabs).
- https://community.silabs.com/068Vm00000211lw
- https://community.silabs.com/s/contentdocument/069Vm000001Gv50
- Experiment videos can be accessed at below two links:
- https://drive.google.com/file/d/1LBycOFbQThFxuGedefVfNqNa0TbTE0R0/view
- https://drive.google.com/file/d/1aZMcGRUVtweYkWlcHzWRsl1jhp1nSBYs/view

### Has vendor confirmed or acknowledged the vulnerability?

true

### Discoverer

Thanks to Carlos Kayembe Nkuba, Jimin Kang, Professor Seunghoon Woo, and Professor Heejo Lee from Korea University for reporting these vulnerabilities.



## 6. CVE-2024-50930

### Suggested description 
An issue in Silicon Labs Z-Wave Series 500 v6.84.0 allows attackers to
execute arbitrary code.
   
  
   
### Vulnerability Type 
Insecure Permissions
   
  
   
### Vendor of Product 
Silicon Labs
   
  
   
### Affected Product Code Base 
Silicon Labs Z-Wave Series 500 devices running v6.84.0 and earlier of the Silicon Labs Series 500 Z-Wave SDK. - Silicon Labs Z-Wave Series 500 devices running v6.84.0 and earlier of the Silicon Labs Series 500 Z-Wave SDK.
   
  
   
### Affected Component 
Silicon Labs Z-Wave Series 500 devices running v6.84.0 and earlier of the Silicon Labs Series 500 Z-Wave SDK.
   
  
   
### Attack Type 
Remote
   
  
   
### Impact Code execution 
true
   
  
   
### Impact Denial of Service 
true
   
  
   
### Attack Vectors 
Z-Wave controller devices based on Silicon Labs 500 series are susceptible to a denial of service via a crafted malformed NEW NODE REGISTERED Command Class. This can be exploited to add rogue 235 fake devices to the controller memory, preventing the addition of new valid devices.
- Exploited Command Class (CMDCL) = 0x01 0x0D
   
  
   
   


### Reference

- https://ccs.korea.ac.kr/pds/Vulnerabilities_in_ZWave.html
- https://github.com/CNK2100/2024-CVE/blob/main/README.md
- Create a free account at https://community.silabs.com to access the response document from the affected vendor, Silicon Labs (SiLabs).
- https://community.silabs.com/068Vm00000211lw
- https://community.silabs.com/s/contentdocument/069Vm000001Gv50
- Experiment videos can be accessed at below two links:
- https://drive.google.com/file/d/1LBycOFbQThFxuGedefVfNqNa0TbTE0R0/view
- https://drive.google.com/file/d/1aZMcGRUVtweYkWlcHzWRsl1jhp1nSBYs/view

### Has vendor confirmed or acknowledged the vulnerability?

true

### Discoverer

Thanks to Carlos Kayembe Nkuba, Jimin Kang, Professor Seunghoon Woo, and Professor Heejo Lee from Korea University for reporting these vulnerabilities.







## 7.  CVE-2024-50931

### Suggested description
Silicon Labs Z-Wave Series 500 v6.84.0 was discovered to contain insecure permissions.


### Vulnerability Type
 Insecure Permissions

### Vendor of Product
 Silicon Labs

### Affected Product Code Base
Silicon Labs Z-Wave Series 500 devices running v6.84.0 and earlier of the Silicon Labs Series 500 Z-Wave SDK. - Silicon Labs Z-Wave Series 500 devices running v6.84.0 and earlier of the Silicon Labs Series 500 Z-Wave SDK.


### Affected Component

Silicon Labs Z-Wave Series 500 devices running v6.84.0 and earlier of the Silicon Labs Series 500 Z-Wave SDK.


### Attack Type
 Remote
 
### Impact Code execution
true
 
### Impact Denial of Service
 true
 
### Attack Vectors
Z-Wave controller devices based on Silicon Labs 500 series are susceptible to a denial
of service via a crafted malformed packets.


### Reference

- https://ccs.korea.ac.kr/pds/Vulnerabilities_in_ZWave.html
- https://github.com/CNK2100/2024-CVE/blob/main/README.md
- Create a free account at https://community.silabs.com to access the response document from the affected vendor, Silicon Labs (SiLabs).
- https://community.silabs.com/068Vm00000211lw
- https://community.silabs.com/s/contentdocument/069Vm000001Gv50
- Experiment videos can be accessed at below two links:
- https://drive.google.com/file/d/1LBycOFbQThFxuGedefVfNqNa0TbTE0R0/view
- https://drive.google.com/file/d/1aZMcGRUVtweYkWlcHzWRsl1jhp1nSBYs/view

### Has vendor confirmed or acknowledged the vulnerability?

true

### Discoverer

Thanks to Carlos Kayembe Nkuba, Jimin Kang, Professor Seunghoon Woo, and Professor Heejo Lee from Korea University for reporting these vulnerabilities.


