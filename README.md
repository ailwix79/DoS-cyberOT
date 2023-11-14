# Industrial Cybersecurity

This repository holds examples of DoS replay attacks following two different approaches:
- Hijacking the current valid session of an HMI communicating with a PLC: [Session hijacking](./DoS_HijackSession.py).
- Establishing a new session between both devices: [New session](./DoS_NewSession.py).

Both the source and destination addresses (MAC and IP) need to be stored in a file called `addresses.json` in the same directory as the Dos files. The JSON format of the file is presented below:

```json
{
    "srcEth" : <src_mac_address>,
    "dstEth" : <dest_mac_address>,
    "srcIP" : <src_ip_address>,
    "dstIP" : <dest_ip_address>
}
```

The protocol files have been acquired from https://github.com/klsecservices/s7scan.