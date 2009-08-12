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

#include <QFile>
#include <QFileDialog>
#include <QSettings>
#include <QMessageBox>

#include "version.h"
#include "settings.h"

extern QSettings *qAppSettings;

Settings::Settings(QWidget *parent, Qt::WindowFlags f)
	: QDialog(parent, f)
{
	setupUi(this);
	lblBuildId->setText(QString("Ver %1 Rev %2").arg(version).arg(revision));

	rbWireshark->setChecked(
		qAppSettings->value("Sniffer").toString() == "Wireshark");
	rbEthereal->setChecked(
		qAppSettings->value("Sniffer").toString() == "Ethereal");
	leSnifferDir->setText(
		qAppSettings->value("SnifferDir").toString());
	leText2PcapExtraArgs->setText(
		qAppSettings->value("Text2PcapExtraArgs").toString());
	leTsharkExtraArgs->setText(
		qAppSettings->value("TsharkExtraArgs").toString());
}

void Settings::accept()
{
	QString dir;

	dir = leSnifferDir->text();

	if (rbWireshark->isChecked())
	{
		if (QFile::exists(QString("%1/%2").arg(dir).arg("text2pcap.exe")) && 
			QFile::exists(QString("%1/%2").arg(dir).arg("tshark.exe")))
		{
			qAppSettings->setValue("Sniffer", "Wireshark");
			qAppSettings->setValue("SnifferDir", dir);
		}
		else
		{
			QMessageBox::information(this, "Wireshark not found", 
				QString("The Wireshark path specified '%1' does not contain"
					" the required applications - 'text2pcap' and 'tshark'").
					arg(dir));
			return;
		}
	}
	else if (rbEthereal->isChecked())
	{
		if (QFile::exists(QString("%1/%2").arg(dir).arg("text2pcap.exe")) && 
			QFile::exists(QString("%1/%2").arg(dir).arg("tethereal.exe")))
		{
			qAppSettings->setValue("Sniffer", "Ethereal");
			qAppSettings->setValue("SnifferDir", dir);
		}
		else
		{
			QMessageBox::information(this, "Ethereal not found", 
				QString("The Ethereal path specified '%1' does not contain"
					" the required applications - 'text2pcap' and 'tethereal'").
				arg(dir));
			return;
		}
	}
	else
	{
		QMessageBox::information(this, "No Sniffer Selected", 
			"Please select one of the sniffer applications!");
		return;
	}

	qAppSettings->setValue("Text2PcapExtraArgs", leText2PcapExtraArgs->text());
	qAppSettings->setValue("TsharkExtraArgs", leTsharkExtraArgs->text());

	emit settingsVerified(true);

	QDialog::accept();
}

void Settings::on_tbBrowse_clicked()
{
	QString dir;

	dir = QFileDialog::getExistingDirectory(this, "Open Directory",
		leSnifferDir->text(), QFileDialog::ShowDirsOnly); 

	if (!dir.isEmpty())
		leSnifferDir->setText(dir);
}
