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

#include <QTextEdit>
#include "ui_hexdumpedit.h"

class HexDumpEdit : public QWidget, Ui::HexDumpEdit
{
	Q_OBJECT
public:
	HexDumpEdit(QWidget* parent = 0);
	QString toPlainText() const;

signals:
	void dumpEmpty(bool isEmpty);


private:
	bool	_isEmpty;
	QString	_text;

	bool isValid(QString str, QByteArray &ba) const;
	bool inline isPrintable(char c) const
		{if ((c > 48) && (c < 126)) return true; else return false; }
	QString asciiDump(QByteArray ba) const;

private slots:
	void on_teInput_textChanged();
};
