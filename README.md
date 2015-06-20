<p align='center'><a href='http://bit.ly/oYBQMe'><img src='http://dl.dropbox.com/u/3968285/banner_ostinato.png' alt='Ostinato - An open-source Packet Crafter/Traffic Generator' /></a></p>
Packet Dump Decode (pdd) is a simple convenient GUI wrapper around the Wireshark/Ethereal tools to convert packet hexdumps into well formatted xml containing the decoded protocols and protocol contents

Using pdd, you just need to copy-paste the hexdump into pdd and hit the "Decode" button.

Convert hexdumps to -
  * Tree-View (within application)
  * Pcap file and open with Wireshark/Ethereal
  * Text description of packet contents
  * XML description of packet contents

NOTE: _pdd is only a wrapper around the Wireshark/Ethereal tools and hence needs either (but at least one) to be already installed_.

| ![http://pdd.googlecode.com/svn/trunk/icons/pdd_screencast.gif](http://pdd.googlecode.com/svn/trunk/icons/pdd_screencast.gif) |
|:------------------------------------------------------------------------------------------------------------------------------|
| **Screencast**<br>(<font color='red'>this is an old version which only supported decode to tree-view</font>)                  </tbody></table>

<h2>Getting Packet Dump Decode ##
_Windows_: Portable 32-bit binary is available in [downloads](http://code.google.com/p/pdd/downloads/list)

_Linux/BSD_: Use the source archive in [downloads](http://code.google.com/p/pdd/downloads/list) to build (Pre-requisite: [Qt4](http://qt.nokia.com/downloads))-
```
$ cd pdd-0.2
$ qmake
$ make
```

## Related Project ##
| [![](http://code.google.com/p/ostinato/logo?logo_id=1270430532&non=sense.png)](http://code.google.com/p/ostinato/) | [Ostinato](http://code.google.com/p/ostinato/) | Packet Generator/Analyzer with a friendly GUI. Aims to be Wireshark-in-Reverse |
|:-------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------|:-------------------------------------------------------------------------------|