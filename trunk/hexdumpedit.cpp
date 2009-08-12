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

#include <qendian.h>
#include <QScrollBar>

#include "hexdumpedit.h"

#define BASE_HEX	16

HexDumpEdit::HexDumpEdit(QWidget* parent)
{
	int w;

	_isEmpty = false;
	setupUi(this);

	setFont(QFont("Courier"));
	w = fontMetrics().width('X');
	teOffset->setMinimumWidth(w * (4 + 1));
	teAscii->setMinimumWidth(w * (16 + 1));

	connect(teOffset->verticalScrollBar(), SIGNAL(valueChanged(int)),
		teInput->verticalScrollBar(), SLOT(setValue(int)));
	connect(teOffset->verticalScrollBar(), SIGNAL(valueChanged(int)),
		teAscii->verticalScrollBar(), SLOT(setValue(int)));
	connect(teInput->verticalScrollBar(), SIGNAL(valueChanged(int)),
		teOffset->verticalScrollBar(), SLOT(setValue(int)));
	connect(teInput->verticalScrollBar(), SIGNAL(valueChanged(int)),
		teAscii->verticalScrollBar(), SLOT(setValue(int)));
	connect(teAscii->verticalScrollBar(), SIGNAL(valueChanged(int)),
		teOffset->verticalScrollBar(), SLOT(setValue(int)));
	connect(teInput->verticalScrollBar(), SIGNAL(valueChanged(int)),
		teInput->verticalScrollBar(), SLOT(setValue(int)));
}

QString HexDumpEdit::toPlainText() const
{
	qDebug("%s", _text.toAscii().constData());
	return _text;
}

bool HexDumpEdit::isValid(QString str, QByteArray &ba) const
{
	bool isOk;
	QStringList l;
	QByteArray v;

	ba.clear();
	l = str.split(' ', QString::SkipEmptyParts);

	foreach(QString s, l)
	{
		ulong x;

		x = s.toULong(&isOk, BASE_HEX);
		if (isOk)
		{
			if (x <= 0xFF)
			{
				v.resize(1);
				qToBigEndian((uchar) x, (uchar*) v.data());
			}
			else if (x <= 0xFFFF)
			{
				v.resize(2);
				qToBigEndian((ushort) x, (uchar*) v.data());
			}
			else
			{
				v.resize(4);
				qToBigEndian((ulong) x, (uchar*) v.data());
			}

			ba.append(v);
		}
		else
			return false;
	}

	if (ba.size())
		return true;
	else
		return false;
}

QString HexDumpEdit::asciiDump(QByteArray ba) const
{
	QString ascii;

	qDebug("%s: %d", __FUNCTION__, ba.size());
	foreach (int c, ba)
	{
		//qDebug("%s: %d", __FUNCTION__, c);

		if (isPrintable(c))
			ascii.append(QChar(c));
		else
			ascii.append(QChar('.'));
	}

	return ascii;
}

void HexDumpEdit::on_teInput_textChanged()
{
	QString t;
	QStringList li, lo, la;
	int ofs = 0;
	QByteArray ba;

	qDebug("In %s", __FUNCTION__);

	_text.clear();

	t = teInput->toPlainText();
	li = t.split('\n');
#if 0
	if (li.size() == 0)
	{
		lvPktList.hide();
		tvPktTree.hide();
	}
	else
	{
		lvPktList.show();
		tvPktTree.show();
	}
#endif
	foreach (QString s, li)
	{
		if (isValid(s, ba))
		{
			QString ofsStr, dumpStr, asciiStr;

			ofsStr = QString("%1").arg(ofs, 4, BASE_HEX, QChar('0'));
			lo.append(ofsStr);
			asciiStr = asciiDump(ba);
			la.append(asciiStr);
			dumpStr = ba.toHex();
			for (int i = dumpStr.size(); i > 0; i -= 2)
				dumpStr.insert(i, QChar(' '));

			_text.append(ofsStr);
			_text.append("  ");
			_text.append(dumpStr);
			_text.append("  ");
			_text.append(asciiStr);
			_text.append('\n');

			ofs += ba.size();
		}
		else
		{
			lo.append(QString());
			la.append(QString());

			_text.append('\n');

			ofs = 0;
		}
	}

	teOffset->setPlainText(lo.join(QString('\n')));
	teAscii->setPlainText(la.join(QString('\n')));

	if (_isEmpty)
	{
		if(t.size()) 
		{
			_isEmpty = false;
			emit dumpEmpty(false);
		}
	}
	else 
	{
		if (t.size() == 0)
		{
			_isEmpty = true;
			emit dumpEmpty(true);
		}
	}

}
