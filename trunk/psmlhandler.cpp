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

#include <QMessageBox>

#include "psmlhandler.h"

PsmlHandler::PsmlHandler(QStandardItemModel *model)
{
    qDebug("%s", __FUNCTION__);

    _model = model;
	isParsingStructure = false;
	isParsingPacket = false;
}

bool PsmlHandler::startElement(const QString & /* namespaceURI */,
	const QString & /* localName */,
	const QString &qName,
	const QXmlAttributes & /* attributes */)
{
    qDebug("%s (%s)", __FUNCTION__, qName.toAscii().constData());

    if (qName == "structure") {
		isParsingStructure = true;
		_sectionCount = 0;
    } else if (qName == "packet") {
		isParsingPacket = true;
		_sectionCount = 0;
		_currentText.clear();
	}
   	else if (qName == "section") 
	{
		_sectionCount++;
	}
    return true;
}

bool PsmlHandler::characters(const QString &str)
{
	QString s;

    qDebug("%s (%s)", __FUNCTION__, str.toAscii().constData());
    s = str.trimmed();
	if (!s.isEmpty())
		if (_currentText.isEmpty())
			_currentText = s;
		else
			_currentText += " | " + s;
    return true;
}

bool PsmlHandler::endElement(const QString & /* namespaceURI */,
                            const QString & /* localName */,
                            const QString &qName)
{
    qDebug("%s (%s)", __FUNCTION__, qName.toAscii().constData());
    if (qName == "structure") 
	{
		isParsingStructure = false;
    }
	else if (qName == "packet") 
	{
		QStandardItem *item;
	
		item = new QStandardItem(_currentText);
		item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
		_model->invisibleRootItem()->appendRow(item);
		qDebug("ITEM --> %s", _currentText.toAscii().constData());

		isParsingPacket = false;
	}
   	else if (qName == "section") 
	{
		if (isParsingStructure)
		{
			if (_currentText == "Info")
				_infoIndex = _sectionCount;
		}
		else if (isParsingPacket)
		{
#if 0
			if (_sectionCount == _infoIndex)
			{
				QStandardItem *item;
			
				item = new QStandardItem(_currentText);
				item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
				_model->invisibleRootItem()->appendRow(item);
				qDebug("ITEM --> %s", _currentText.toAscii().constData());
			}
#endif
		}
	}

    return true;
}

bool PsmlHandler::fatalError(const QXmlParseException &exception)
{
    qDebug("%s", __FUNCTION__);
    QMessageBox::warning(0, QObject::tr("PSML Handler"),
                         QObject::tr("Parse error at line %1, column "
                                     "%2:\n%3.")
                         .arg(exception.lineNumber())
                         .arg(exception.columnNumber())
                         .arg(exception.message()));
    return false;
}

