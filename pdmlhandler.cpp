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
			QString		val;
			val = attributes.value("showname");
			if (val.isEmpty())
				val = attributes.value("show");
			if (!val.isEmpty())
			{
				item = new QStandardItem(val);
				item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
				currentItem->appendRow(item);
				currentItem = item;
				//qDebug("ITEM(%p) --> %s", item, attributes.value("showname").toAscii().constData());
			}
			else
				skip = true;
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
		{
			lastElement = qName + currentItem->text().section(':',0,0);
			currentItem = _model->itemFromIndex(
				_model->indexFromItem(currentItem).parent());
		}
	}

    return true;
}

bool PdmlHandler::fatalError(const QXmlParseException &exception)
{
	QString extra;

    qDebug("%s", __FUNCTION__);
	if (exception.message() == "tag mismatch" && lastElement == "fieldData")
		extra = "\nAre you using an old version of Wireshark? If so, try using a newer version. Alternatively, view the packet dump decode in Wireshark by clicking the \"External\" button.";

    QMessageBox::warning(0, QObject::tr("PDML Parser"),
                         QObject::tr("XML parse error for packet %1 "
							"at line %2, column %3:\n    %4\n%5")
                         .arg(packetCount+1)
                         .arg(exception.lineNumber())
                         .arg(exception.columnNumber())
                         .arg(exception.message())
						 .arg(extra));
    return false;
}

