/* rgpackagestatus.cc  - package status UI stuff
 * 
 * Copyright (c) 2003 Michael Vogt
 * 
 * Author: Michael Vogt <mvo@debian.org>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <gtk/gtk.h>
#include <string>
#include <stdio.h>
#include <math.h>
#include <cstdlib>
#include <cstring>

#include "rgutils.h"
#include "rgpackagestatus.h"

#include "jsonparse.h"
#include "rvinfo.h"
#include <stdexcept>


static unordered_map<string, RVInfo> pkgMap = getMap();

// RPackageStatus stuff
RGPackageStatus RGPackageStatus::pkgStatus;

void RGPackageStatus::initColors()
{
   const char *default_status_colors[N_STATUS_COUNT] = {
      "#8ae234",  // install
      "#4e9a06",  // re-install
      "#fce94f",  // upgrade
      "#ad7fa8",  // downgrade
      "#ef2929",  // remove
      "#a40000",  // purge
      NULL,       // available
      "#a40000",  // available-locked
      NULL,       // installed-updated
      NULL,       // installed-outdated
      "#a40000",  // installed-locked 
      NULL,       // broken
      NULL        // new
   };

   gchar *config_string;
   for (int i = 0; i < N_STATUS_COUNT; i++) {
      config_string = g_strdup_printf("Synaptic::color-%s",
                                      PackageStatusShortString[i]);
      gtk_get_color_from_string(_config->
                                Find(config_string,
                                     default_status_colors[i]).c_str(),
                                &StatusColors[i]);
      g_free(config_string);
   }
}

void RGPackageStatus::initPixbufs()
{
   gchar *s;
   for (int i = 0; i < N_STATUS_COUNT; i++) {
      s = g_strdup_printf("package-%s", PackageStatusShortString[i]);
      StatusPixbuf[i] = get_gdk_pixbuf(s);
   }
   supportedPix = get_gdk_pixbuf("package-supported");
}

// class that finds out what do display to get user
void RGPackageStatus::init()
{
   RPackageStatus::init();

   initColors();
   initPixbufs();
}


GdkColor *RGPackageStatus::getBgColor(RPackage *pkg)
{
   return StatusColors[getStatus(pkg)];
}

GdkPixbuf *RGPackageStatus::getSupportedPix(RPackage *pkg)
{
   if(isSupported(pkg))
      return supportedPix;
   else
      return NULL;
}

GdkPixbuf *RGPackageStatus::getPixbuf(RPackage *pkg)
{
   return StatusPixbuf[getStatus(pkg)];
}

GdkPixbuf *RGPackageStatus::getRisk(RPackage *pkg)
{
   GdkPixbuf *pix;
   GError *error = NULL;
   RVInfo rvInfo;
   double risk_score;
   std::stringstream sstm;
   try {
      rvInfo = pkgMap.at(pkg->name());
      risk_score = rvInfo.getUpdatedRisk();
      risk_score = floor(risk_score * 20 / 10);
      sstm << "/usr/local/share/synaptic/gtkbuilder/images/bar" << (int)risk_score << ".png";
   } catch (const std::out_of_range& oor) {
      sstm << "/usr/local/share/synaptic/gtkbuilder/images/bar_.png";
   }
   pix = gdk_pixbuf_new_from_file((sstm.str()).c_str(), &error);
   if(error){
      g_warning("risk score not loading: %s", error->message);
      g_error_free(error);
      error = NULL;
   }
   return pix;
}

GdkPixbuf *RGPackageStatus::getRiskFromName(const char *name)
{
   GdkPixbuf *pix;
   GError *error = NULL;
   RVInfo rvInfo;
   double risk_score;
   std::stringstream sstm;
   try {
      rvInfo = pkgMap.at(name);
      risk_score = rvInfo.getUpdatedRisk();
      risk_score = floor(risk_score * 20 / 10);
      sstm << "/usr/local/share/synaptic/gtkbuilder/images/bar" << (int)risk_score << ".png";
   } catch (const std::out_of_range& oor) {
      sstm << "/usr/local/share/synaptic/gtkbuilder/images/bar_.png";
   }
   pix = gdk_pixbuf_new_from_file((sstm.str()).c_str(), &error);
   if(error){
      g_warning("risk score not loading: %s", error->message);
      g_error_free(error);
      error = NULL;
   }
   return pix;
}

GdkPixbuf *RGPackageStatus::getCurrRisk(RPackage *pkg)
{
   GdkPixbuf *pix;
   GError *error = NULL;
   RVInfo rvInfo;
   double risk_score;
   std::stringstream sstm;
   try {
      rvInfo = pkgMap.at(pkg->name());
      risk_score = rvInfo.getCurrRisk(pkg->installedVersion());
      risk_score = floor(risk_score * 20 / 10);
      sstm << "/usr/local/share/synaptic/gtkbuilder/images/bar" << (int)risk_score << ".png";
   } catch (const std::out_of_range& oor) {
      sstm << "/usr/local/share/synaptic/gtkbuilder/images/bar_.png";
   }
   pix = gdk_pixbuf_new_from_file((sstm.str()).c_str(), &error);
   if(error){
      g_warning("risk score not loading: %s", error->message);
      g_error_free(error);
      error = NULL;
   }
   return pix;
}

GdkPixbuf *RGPackageStatus::getUpRisk(RPackage *pkg)
{
   GdkPixbuf *pix;
   GError *error = NULL;
   RVInfo rvInfo;
   double risk_score;
   double risk_score_new;
   const char* change;
   std::stringstream sstm;
   try {
      rvInfo = pkgMap.at(pkg->name());
      risk_score = rvInfo.getCurrRisk(pkg->installedVersion());
      risk_score_new = rvInfo.getUpdatedRisk();
      change = (risk_score_new > risk_score) ? "+.png" : "-.png";
      sstm << "/usr/local/share/synaptic/gtkbuilder/images/bar"
           << abs((int)floor(risk_score_new * 20 / 10) - (int)floor(risk_score * 20 / 10))
           << change;
   } catch (const std::out_of_range& oor) {
      sstm << "/usr/local/share/synaptic/gtkbuilder/images/bar_.png";
   }
   pix = gdk_pixbuf_new_from_file((sstm.str()).c_str(), &error);
   if(error){
      g_warning("risk score not loading: %s", error->message);
      g_error_free(error);
      error = NULL;
   }
   return pix;
}

void RGPackageStatus::setColor(int i, GdkColor * new_color)
{
   StatusColors[i] = new_color;
}

void RGPackageStatus::saveColors()
{
   gchar *color_string, *config_string;
   for (int i = 0; i < N_STATUS_COUNT; i++) {
      color_string = gtk_get_string_from_color(StatusColors[i]);
      config_string = g_strdup_printf("Synaptic::color-%s",
                                      PackageStatusShortString[i]);

      _config->Set(config_string, color_string);
      g_free(config_string);
   }
}
