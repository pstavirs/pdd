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

#include <QString>
#include <QStringList>
#include <QScrollBar>
#include <QXmlSimpleReader>
#include <QXmlInputSource>
#include <QHeaderView>
#include <QSettings>

#include "pktdumpdecode.h"
#include "settings.h"

#define Q_UNREACHABLE() Q_ASSERT(1 == 0)

extern QSettings *qAppSettings;

PktView::PktView()
{
	qDebug("in %s", __FUNCTION__);

	logFile = QString("%1/%2")
		.arg(QCoreApplication::applicationDirPath())
		.arg("pdd.log");

	view = vw_none;

	packetModel = new QStandardItemModel;
	//xmlReader = new QXmlSimpleReader;

	setupUi(this);
	tvPktTree->setModel(packetModel);
	tvPktTree->header()->setVisible(false);
	tvPktTree->hide();

	pcapFile = new QTemporaryFile;
	if (!pcapFile->open())
		qFatal("Unable to open temp pcap file");
	qDebug("pcap file = %s", pcapFile->fileName().toAscii().constData());

	xmlFile = NULL;

	connect(&t2p, SIGNAL(started()), this, SLOT(when_t2p_started()));
	connect(&t2p, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(when_t2p_finished()));

	connect(&ts, SIGNAL(started()), this, SLOT(when_ts_started()));
	connect(&ts, SIGNAL(readyRead()), this, SLOT(when_ts_readyRead()));
	connect(&ts, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(when_ts_finished()));

	teInputDump->setFocus(Qt::OtherFocusReason);
}

PktView::~PktView()
{
	pcapFile->close();
	delete pcapFile;
	if (xmlFile)
		delete xmlFile;

	//delete xmlReader;
	delete packetModel;
}

void PktView::on_tbSettings_clicked()
{
	Settings	settings;

	connect(&settings, SIGNAL(settingsVerified(bool)),
		this, SLOT(snifferVerified(bool)));
	settings.exec();
}

void PktView::snifferVerified(bool isVerified)
{
	qDebug("Sniffer verified = %d", isVerified);
	if (isVerified)
	{
		t2pProg = qAppSettings->value("SnifferDir").toString()+"/text2pcap.exe";
		tsProg = qAppSettings->value("SnifferDir").toString()+"/";
		extProg = qAppSettings->value("SnifferDir").toString()+"/";
		if (qAppSettings->value("Sniffer").toString() == "Wireshark")
		{
			tsProg.append("tshark");
			extProg.append("wireshark");
		}
		else if (qAppSettings->value("Sniffer").toString() == "Ethereal")
		{
			tsProg.append("tethereal");
			extProg.append("ethereal");
		}
		else
			qFatal("No sniffer selected");

		t2pExtraArgs = qAppSettings->value("Text2PcapExtraArgs").toString();
		tsExtraArgs = qAppSettings->value("TsharkExtraArgs").toString();

		qDebug("Setting t2pProg = %s", t2pProg.toAscii().constData());
		qDebug("Setting tsProg = %s", tsProg.toAscii().constData());
		qDebug("Setting t2pExtraArgs = %s", t2pExtraArgs.toAscii().constData());
		qDebug("Setting tsExtraArgs = %s", tsExtraArgs.toAscii().constData());
	}

	tbDecode->setEnabled(isVerified);
}

void PktView::start_t2p()
{
	qDebug("%s", __FUNCTION__);

	tvPktTree->setDisabled(true);
	tvPktTree->show();

	//t2p.setProcessChannelMode(QProcess::MergedChannels);

	qDebug("Starting text2pcap ...");

	t2p.setStandardErrorFile(logFile, QIODevice::Truncate);

	t2p.start(t2pProg, QStringList(QString("-ohex %1").arg(qAppSettings->value(
			"Text2PcapExtraArgs").toString())) << "-" << pcapFile->fileName());
}

void PktView::on_tbDecode_clicked()
{
	qDebug("%s", __FUNCTION__);

	view = vw_internal;
	tbDecode->setDisabled(true);
	start_t2p();
}

void PktView::on_tbViewExternal_clicked()
{
	qDebug("%s", __FUNCTION__);

	view = vw_external;
	tbViewExternal->setDisabled(true);
	start_t2p();
}

void PktView::on_tbViewXml_clicked()
{
	qDebug("%s", __FUNCTION__);

	view = vw_xml;
	tbViewXml->setDisabled(true);
	start_t2p();
}

void PktView::when_t2p_started()
{
	QByteArray ba;

	qDebug("... text2pcap running (view = %d)", view);

	switch (view)
	{
		case vw_internal:
		case vw_external:
		case vw_xml:
			ba.append(teInputDump->toPlainText());
			qDebug("Writing %d dump bytes to text2pcap", ba.size());
			if (ba.size())
				t2p.write(ba);
			qDebug("Finished writing to text2pcap");
			t2p.closeWriteChannel();
			break;
		default:
			Q_UNREACHABLE();
	}
}

void PktView::when_t2p_finished()
{
	qDebug("text2pcap finished (view = %d)", view);

	packetModel->clear();

	switch (view)
	{
		case vw_internal:
			ts.readAll();
			inDetailedDecode = false;
			xmlSource = new QXmlInputSource(&ts);
			xmlSource->reset();
			xmlReader = new QXmlSimpleReader;
			psml = new PsmlHandler(packetModel);
			xmlReader->setContentHandler(psml);
			xmlReader->setErrorHandler(psml);

			ts.setStandardErrorFile(logFile, QIODevice::Append);
			qDebug("Starting %s ...", tsProg.toAscii().constData());

			ts.start(tsProg, QStringList(qAppSettings->value(
				"TsharkExtraArgs").toString()) << "-Tpsml" << QString("-r%1").arg(
				pcapFile->fileName()));
			break;
		case vw_external:
			ts.setStandardErrorFile(logFile, QIODevice::Append);
			qDebug("Starting %s ...", extProg.toAscii().constData());

			ts.start(extProg, QStringList() << QString("-r%1").arg(
				pcapFile->fileName()));
			break;
		case vw_xml:
			//ts.setStandardOutputFile(xmlFile->fileName(), QIODevice::Append);
			if (xmlFile)
				delete xmlFile;
			xmlFile = new QTemporaryFile;
			if (!xmlFile->open())
				qFatal("Unable to open temp xml file");
			qDebug("xml file = %s", xmlFile->fileName().toAscii().constData());

			ts.readAll();
			qDebug("Starting %s ...", tsProg.toAscii().constData());

			ts.start(tsProg, QStringList(qAppSettings->value(
				"TsharkExtraArgs").toString()) << "-Tpdml" << QString("-r%1").arg(
				pcapFile->fileName()));
			break;
		default:
			Q_UNREACHABLE();
	}
}

void PktView::when_ts_started()
{
	qDebug("tshark/wireshark started (view = %d)", view);
	qDebug("%s (%d)", tsProg.toAscii().constData(), inDetailedDecode);

	switch(view)
	{
		case vw_internal:
			isFirstTime = true;
			break;
		case vw_external:
			tbViewExternal->setEnabled(true);
			view = vw_none;
			break;
		case vw_xml:
			break;
		default:
			Q_UNREACHABLE();
	}
}

void PktView::when_ts_readyRead()
{
	bool isOk;

	qDebug("%s (view = %d) inDetailed = %d", __FUNCTION__, view, 
		inDetailedDecode);

	switch(view)
	{
		case vw_internal:
			if (isFirstTime)
			{
				isOk = xmlReader->parse(xmlSource, true);
				isFirstTime = false;
			}
			else
				isOk = xmlReader->parseContinue();

			qDebug("isOk = %d", isOk);
			break;
		case vw_external:
			// DO Nothing
			Q_UNREACHABLE();
			break;
		case vw_xml:
		{
			char buf[1024];
			int  n;

			do 
			{
				n = ts.read(buf, sizeof(buf));
				if (n)
					xmlFile->write(buf, n);
			} while (n > 0);
		}
			break;
		default:
			Q_UNREACHABLE();
	}
}

void PktView::when_ts_finished()
{
	qDebug("%s (view = %d) inDetailed = %d", __FUNCTION__, view, 
		inDetailedDecode);

	switch(view)
	{
		case vw_internal:
			// Finish up reading any data left over
			while (xmlReader->parseContinue());


			if (!inDetailedDecode)
			{
				inDetailedDecode = true;
				isFirstTime = true;

				delete psml;
				delete xmlReader;
				delete xmlSource;
				xmlSource = new QXmlInputSource(&ts);
				xmlSource->reset();
				xmlReader = new QXmlSimpleReader;
				pdml = new PdmlHandler(packetModel);
				xmlReader->setContentHandler(pdml);
				xmlReader->setErrorHandler(pdml);

				ts.start(tsProg, QStringList(qAppSettings->value(
					"TsharkExtraArgs").toString()) << "-Tpdml" << QString("-r%1").arg(
					pcapFile->fileName()));
			}
			else
			{
				inDetailedDecode = false;
				view = vw_none;
				tvPktTree->setEnabled(true);
				tbDecode->setEnabled(true);
				delete pdml;
				delete xmlReader;
				delete xmlSource;
			}
			break;
		case vw_external:
			// Do Nothing!
			break;
		case vw_xml:
		{
			char buf[1024];
			int  n;

			do 
			{
				n = ts.read(buf, sizeof(buf));
				if (n)
					xmlFile->write(buf, n);
			} while (n > 0);
			xmlFile->flush();

			view = vw_none;
			QProcess::startDetached("notepad", QStringList() << xmlFile->fileName());
			tvPktTree->setEnabled(true);
			tbViewXml->setEnabled(true);
		}
			break;
		default:
			break;
	}
}

