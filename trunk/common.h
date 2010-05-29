/*
Packet Dump Decode (pdd) - Decode a packet hex dump
Copyright (C) 2010 Srivats P.

This file is part of Packet Dump Decode (pdd)

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

#ifndef _COMMON_H
#define _COMMON_H

#ifdef Q_OS_WIN32
const QString kDefaultWiresharkDir = "C:/Program Files/Wireshark/";
const QString kDefaultEtherealDir = "C:/Program Files/Ethereal/";
const QString kExt = ".exe";
const QString kDefaultTextViewer = "C:/Windows/notepad.exe";
#else
const QString kDefaultWiresharkDir = "/usr/bin/";
const QString kDefaultEtherealDir = "/usr/bin/";
const QString kExt = "";
const QString kDefaultTextViewer = "/usr/bin/gvim";
#endif

#endif
