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

extern QSettings *qAppSettings;

PktView::PktView()
{
	qDebug("in %s", __FUNCTION__);

	logFile = QString("%1/%2")
		.arg(QCoreApplication::applicationDirPath())
		.arg("pdd.log");
	packetModel = new QStandardItemModel;
	psml = new PsmlHandler(packetModel);
	pdml = new PdmlHandler(packetModel);
	xmlReader = new QXmlSimpleReader;

	setupUi(this);
	tvPktTree->setModel(packetModel);
	tvPktTree->header()->setVisible(false);
	tvPktTree->hide();

	pcapFile = new QTemporaryFile;
	if (!pcapFile->open())
		qFatal("Unable to open temp file");
	qDebug("pcap file = %s", pcapFile->fileName().toAscii().constData());

	connect(&t2p, SIGNAL(started()), this, SLOT(when_t2p_started()));
	connect(&t2p, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(when_t2p_finished()));

	connect(&ts, SIGNAL(started()), this, SLOT(when_ts_started()));
	connect(&ts, SIGNAL(readyRead()), this, SLOT(when_ts_readyRead()));
	connect(&ts, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(when_ts_finished()));
}

PktView::~PktView()
{
	pcapFile->close();
	delete pcapFile;

	delete xmlReader;
	delete psml;
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
		if (qAppSettings->value("Sniffer").toString() == "Wireshark")
			tsProg.append("tshark");
		else if (qAppSettings->value("Sniffer").toString() == "Ethereal")
			tsProg.append("tethereal");
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

void PktView::on_tbDecode_clicked()
{
	qDebug("%s", __FUNCTION__);

	tbDecode->setDisabled(true);
	tvPktTree->setDisabled(true);
	tvPktTree->show();

	//t2p.setProcessChannelMode(QProcess::MergedChannels);

	qDebug("Starting text2pcap ...");

	t2p.setStandardErrorFile(logFile, QIODevice::Truncate);

	t2p.start(t2pProg, QStringList(QString("-ohex %1").arg(qAppSettings->value(
			"Text2PcapExtraArgs").toString())) << "-" << pcapFile->fileName());
}

void PktView::when_t2p_started()
{
	QByteArray ba;

	qDebug("... text2pcap running");
	ba.append(teInputDump->toPlainText());
	qDebug("Writing %d dump bytes to text2pcap", ba.size());
	if (ba.size())
		t2p.write(ba);
	qDebug("Finished writing to text2pcap");
	t2p.closeWriteChannel();
}

void PktView::when_t2p_finished()
{
	QString prog;

	qDebug("text2pcap finished");

	inDetailedDecode = false;
	packetModel->clear();
	xmlSource = new QXmlInputSource(&ts);
	xmlReader->setContentHandler(psml);
	xmlReader->setErrorHandler(psml);

	ts.setStandardErrorFile(logFile, QIODevice::Append);
	qDebug("Starting %s ...", tsProg.toAscii().constData());

	ts.start(tsProg, QStringList(qAppSettings->value(
		"TsharkExtraArgs").toString()) << "-Tpsml" << QString("-r%1").arg(
		pcapFile->fileName()));
}

void PktView::when_ts_started()
{
	qDebug("%s (%d)", tsProg.toAscii().constData(), inDetailedDecode);
	isFirstTime = true;
}

void PktView::when_ts_readyRead()
{
	bool isOk;

	qDebug("%s (%d)", __FUNCTION__, inDetailedDecode);
	if (isFirstTime)
	{
		isOk = xmlReader->parse(xmlSource, true);
		isFirstTime = false;
	}
	else
		isOk = xmlReader->parseContinue();

	qDebug("isOk = %d", isOk);
}

void PktView::when_ts_finished()
{
	qDebug("%s (%d)", __FUNCTION__, inDetailedDecode);

	// Finish up reading any data left over
	while (xmlReader->parseContinue());

	delete xmlSource;

	if (!inDetailedDecode)
	{
		inDetailedDecode = true;
		xmlSource = new QXmlInputSource(&ts);
		xmlReader->setContentHandler(pdml);
		xmlReader->setErrorHandler(pdml);
		isFirstTime = true;

		ts.start(tsProg, QStringList(qAppSettings->value(
			"TsharkExtraArgs").toString()) << "-Tpdml" << QString("-r%1").arg(
			pcapFile->fileName()));
	}
	else
	{
		tvPktTree->setEnabled(true);
		tbDecode->setEnabled(true);
		inDetailedDecode = false;
	}
}

