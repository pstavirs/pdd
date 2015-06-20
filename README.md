## Packet Dump Decode
Packet Dump Decode (pdd) is a simple convenient GUI wrapper around the Wireshark/Ethereal tools to convert packet hexdumps into well formatted xml containing the decoded protocols and protocol contents

Using pdd, you just need to copy-paste the hexdump into pdd and hit the "Decode" button.

Convert hexdumps to -
  * Tree-View (within application)
  * Pcap file and open with Wireshark/Ethereal
  * Text description of packet contents
  * XML description of packet contents

NOTE: _pdd is only a wrapper around the Wireshark/Ethereal tools and hence needs either (but at least one) to be already installed_.

**Screencast** (of an old version which only supported decode to tree-view) -
![PDD Screencast](https://raw.githubusercontent.com/pstavirs/pdd/master/icons/pdd_screencast.gif)

Win32 Binary and Source downloads are available at [BinTray](https://bintray.com/pstavirs/pdd)

To compile from source, you need Qt4 development libraries. To build -
```
$ qmake
$ make
```
