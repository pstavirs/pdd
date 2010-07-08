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

#include "settings.h"

#include <QFile>
#include <QFileDialog>
#include <QSettings>
#include <QMessageBox>

#include "common.h"

extern char* version;
extern char* revision;

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

	leTextViewer->setText(
		qAppSettings->value("TextViewer").toString());
}

void Settings::accept()
{
	QString dir;

	dir = leSnifferDir->text();

	if (rbWireshark->isChecked())
	{
		if (QFile::exists(QString("%1/%2").arg(dir).arg("text2pcap"+kExt)) && 
			QFile::exists(QString("%1/%2").arg(dir).arg("tshark"+kExt)))
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
		if (QFile::exists(QString("%1/%2").arg(dir).arg("text2pcap"+kExt)) && 
			QFile::exists(QString("%1/%2").arg(dir).arg("tethereal"+kExt)))
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

	if (!QFile::exists(leTextViewer->text()))
	{
		QMessageBox::information(this, "Text Viewer not found", 
			QString("The text viewer specified '%1' does not exist").
				arg(leTextViewer->text()));
		return;
	}

	if (!(QFile::permissions(leTextViewer->text()) & QFile::ExeUser))
	{
		QMessageBox::information(this, "Text Viewer not executable", 
			QString("The text viewer '%1' does not appear"
			     	" to be an executable application.")
					.arg(leTextViewer->text()));
		return;
	}

	qAppSettings->setValue("TextViewer", leTextViewer->text());
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

void Settings::on_tbBrowseFile_clicked()
{
	QString prog;

	prog = QFileDialog::getOpenFileName(this, "Select Text Viewer",
		leTextViewer->text()); 

	if (!prog.isEmpty())
		leTextViewer->setText(prog);
}
