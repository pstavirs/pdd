/*
Packet Dump Decode (pdd) - Decode a packet hex dump
Copyright (C) Srivats P.

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

#include <QApplication>
#include <QSettings>
#include <QMessageBox>

#include "pktdumpdecode.h"

QSettings *qAppSettings;

int main(int argc, char *argv[])
{
	bool verified = true;
	int status;
	PktView *pktView;
    QApplication app(argc, argv);

	qAppSettings = new QSettings(QString("%1/%2").arg(
		QCoreApplication::applicationDirPath()).arg("pdd.ini"),
		QSettings::IniFormat);

	if (!qAppSettings->contains("Sniffer") || !qAppSettings->contains("SnifferDir"))
	{
		// Try to auto-locate Wireshark, then Ethereal otherwise inform user
		if (QFile::exists("C:/Program Files/Wireshark/tshark.exe") &&
			QFile::exists("C:/Program Files/Wireshark/text2pcap.exe"))
		{
			qAppSettings->setValue("Sniffer", "Wireshark");
			qAppSettings->setValue("SnifferDir", "C:/Program Files/Wireshark");
		}
		else if (QFile::exists("C:/Program Files/Ethereal/tethereal.exe") &&
			QFile::exists("C:/Program Files/Ethereal/text2pcap.exe"))
		{
			qAppSettings->setValue("Sniffer", "Ethereal");
			qAppSettings->setValue("SnifferDir", "C:/Program Files/Ethereal");
		}
		else
		{
			verified = false;
			QMessageBox::information(NULL, "Sniffer not found",
			   "Packet Dump Decode could not auto-locate either Wireshark"
			   " or Ethereal. Please configure location manually in the"
			   " 'Settings' dialog\n\nNOTE: Packet Dump Decode needs either"
			   " Wireshark or Ethereal installed to be able to work");
		}
	}

	pktView = new PktView;
	pktView->snifferVerified(verified);
    pktView->show();
    status = app.exec();

	delete qAppSettings;

	return status;
} 
