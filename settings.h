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

#include <QDialog>

#include "ui_settings.h"

class Settings : public QDialog, Ui::Settings
{
	Q_OBJECT
public:
	Settings(QWidget *parent=0, Qt::WindowFlags f=0);

public slots:
	virtual void accept();

signals:
	void settingsVerified(bool isVerified);

private slots:
	void on_tbBrowse_clicked();
};
