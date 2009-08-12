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

#include <QStandardItemModel>

#include <QMessageBox>

#include "pdmlhandler.h"

PdmlHandler::PdmlHandler(QStandardItemModel *model)
{
    qDebug("%s", __FUNCTION__);

    _model = model;
	skip = false;
}

bool PdmlHandler::startElement(const QString & /* namespaceURI */,
	const QString & /* localName */,
	const QString &qName,
	const QXmlAttributes &attributes)
{
    qDebug("%s (%s)", __FUNCTION__, qName.toAscii().constData());
    if (qName == "pdml") 
	{
		packetCount = 0;
	}
	else if (qName == "packet") 
	{
		currentItem = _model->item(packetCount, 0);
    }
	else if ((qName == "proto") || (qName == "field"))
	{
		QStandardItem *item;

		if (attributes.value("hide") == "yes")
		{
			skip = true;
		}
		else 
		{
			item = new QStandardItem(attributes.value("showname"));
			item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
			currentItem->appendRow(item);
			currentItem = item;
			//qDebug("ITEM(%p) --> %s", item, attributes.value("showname").toAscii().constData());
		}
	}
    return true;
}

bool PdmlHandler::characters(const QString &str)
{
    //qDebug("%s (%s)", __FUNCTION__, str.toAscii().constData());
    _currentText += str;
    return true;
}

bool PdmlHandler::endElement(const QString & /* namespaceURI */,
                            const QString & /* localName */,
                            const QString &qName)
{
    qDebug("%s (%s)", __FUNCTION__, qName.toAscii().constData());

    if (qName == "packet") 
	{
		packetCount++;
    }
	else if ((qName == "proto") || (qName == "field"))
	{
		if (skip)
			skip = false;
		else 
			currentItem = _model->itemFromIndex(
				_model->indexFromItem(currentItem).parent());
	}

    return true;
}

bool PdmlHandler::fatalError(const QXmlParseException &exception)
{
    qDebug("%s", __FUNCTION__);
    QMessageBox::warning(0, QObject::tr("PDML Handler"),
                         QObject::tr("Parse error at line %1, column "
                                     "%2:\n%3.")
                         .arg(exception.lineNumber())
                         .arg(exception.columnNumber())
                         .arg(exception.message()));
    return false;
}

