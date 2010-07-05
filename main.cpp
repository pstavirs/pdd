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

#include "common.h"
#include "pktdumpdecode.h"

QSettings *qAppSettings;

int main(int argc, char *argv[])
{
	bool snifferVerified = true;
	bool textViewerVerified = true;
	int status;
	PktView *pktView;
    QApplication app(argc, argv);

	qAppSettings = new QSettings(QString("%1/%2").arg(
		QCoreApplication::applicationDirPath()).arg("pdd.ini"),
		QSettings::IniFormat);

	if (!qAppSettings->contains("TextViewer"))
	{
		// Try to auto-locate the default text viewer, otherwise inform user
		if (QFile::exists(kDefaultTextViewer) &&
				(QFile::permissions(kDefaultTextViewer) & QFile::ExeUser))
		{
			qAppSettings->setValue("TextViewer", kDefaultTextViewer);
		}
		else
		{
			textViewerVerified = false;
			QMessageBox::information(NULL, "Text Viewer not found",
			   "Packet Dump Decode could not auto-locate a text viewer"
			   " application. Please configure location manually in the"
			   " 'Settings' dialog (You will not be able to decode to"
			   " XML)\n\nNOTE: Normal decoding will still work!");
		}
	}

	if (!qAppSettings->contains("Sniffer") || !qAppSettings->contains("SnifferDir"))
	{
		// Try to auto-locate Wireshark, then Ethereal otherwise inform user
		if (QFile::exists(kDefaultWiresharkDir+"/tshark"+kExt) &&
			QFile::exists(kDefaultWiresharkDir+"/text2pcap"+kExt) &&
			QFile::exists(kDefaultWiresharkDir+"/wireshark"+kExt))
		{
			qAppSettings->setValue("Sniffer", "Wireshark");
			qAppSettings->setValue("SnifferDir", kDefaultWiresharkDir);
		}
		else if (QFile::exists(kDefaultEtherealDir+"/tethereal"+kExt) &&
			QFile::exists(kDefaultEtherealDir+"/text2pcap"+kExt) &&
			QFile::exists(kDefaultEtherealDir+"/ethereal"+kExt))
		{
			qAppSettings->setValue("Sniffer", "Ethereal");
			qAppSettings->setValue("SnifferDir", kDefaultEtherealDir);
		}
		else
		{
			snifferVerified = false;
			QMessageBox::information(NULL, "Sniffer not found",
			   "Packet Dump Decode could not auto-locate either Wireshark"
			   " or Ethereal. Please configure location manually in the"
			   " 'Settings' dialog\n\nNOTE: Packet Dump Decode needs either"
			   " Wireshark or Ethereal installed to be able to work");
		}
	}

	pktView = new PktView;
	pktView->snifferVerified(snifferVerified);
	pktView->textViewerVerified(textViewerVerified);
	pktView->setWindowFlags(Qt::Window);
    pktView->show();
    status = app.exec();
	delete qAppSettings;

	return status;
} 
