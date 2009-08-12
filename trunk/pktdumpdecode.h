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

#include <QTemporaryFile>
#include <QProcess>

#include "ui_pktdumpdecode.h"
#include "psmlhandler.h"
#include "pdmlhandler.h"

class PktView : public QDialog, Ui::PktView
{
	Q_OBJECT

public:
	PktView();
	~PktView();

public slots:
	void on_tbDecode_clicked();
	void on_tbSettings_clicked();
	void snifferVerified(bool isVerified);

private:
	QString			t2pProg, t2pExtraArgs;
	QString			tsProg, tsExtraArgs;
	QString			logFile;
	QTemporaryFile	*pcapFile;
	QProcess		t2p;
	QProcess		ts;
	bool			inDetailedDecode;

	QStandardItemModel	*packetModel;

	QXmlSimpleReader	*xmlReader;
	QXmlInputSource		*xmlSource;
	PsmlHandler			*psml;
	PdmlHandler			*pdml;

	bool				isFirstTime;

private slots:
	void when_t2p_started();
	void when_t2p_finished();
	void when_ts_started();
	void when_ts_readyRead();
	void when_ts_finished();
};
