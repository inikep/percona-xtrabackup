/******************************************************
Copyright (c) 2018 Percona LLC and/or its affiliates.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

*******************************************************/

#include <my_rapidjson_size_t.h>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include <fil0fil.h>

#include <fstream>

#include "space_map.h"
#include "common.h"
#include "xb0xb.h"

Tablespace_map Tablespace_map::static_tablespace_map;

const char *XBTS_FILE_NAME = "xtrabackup_tablespaces";
const int XBTS_FILE_VERSION = 1;

/** Add file to tablespace map.
@param[in]  file_name file name
@param[in]  tablespace_name corresponding tablespace name */
void
xb_tablespace_map_add(const char *file_name, const char *tablespace_name) {
  Tablespace_map::instance().add(file_name, tablespace_name);
}

/** Delete tablespace mapping.
@param[in]  tablespace_name tablespace name */
void
xb_tablespace_map_delete(const char *tablespace_name) {
  Tablespace_map::instance().erase(tablespace_name);
}

/** Lookup backup file name for given file.
@param[in]  file_name file name
@return   local file name */
std::string
xb_tablespace_backup_file_path(const std::string &file_name) {
  return Tablespace_map::instance().backup_file_name(file_name);
}

Tablespace_map &Tablespace_map::instance() {
  return (static_tablespace_map);
}

/** Scan I_S.FILES for extended tablespaces.
@param[in]  connection MySQL connection object */
void Tablespace_map::scan(MYSQL *connection) {
  const char *query = "SELECT FILE_NAME, TABLESPACE_NAME"
                      "  FROM INFORMATION_SCHEMA.FILES"
                      "  WHERE ENGINE = 'InnoDB'"
                      "    AND STATUS = 'NORMAL'"
                      "    AND FILE_TYPE <> 'TEMPORARY'"
                      "    AND FILE_TYPE <> 'UNDO LOG'"
                      "    AND FILE_ID <> 0";
  MYSQL_RES *mysql_result;
  MYSQL_ROW row;

  mysql_result = xb_mysql_query(connection, query, true);

  while ((row = mysql_fetch_row(mysql_result)) != nullptr) {
    std::string file_name = row[0];
    std::string tablespace_name = row[1];

    add(file_name, tablespace_name);
  }

  mysql_free_result(mysql_result);
}

/** Add tablespace to the list.
@param[in]  file_name tablespace file name
@param[in]  tablespace_name tablespace name */
void Tablespace_map::add(const std::string &file_name,
                         const std::string &tablespace_name) {
  char full_path[FN_REFLEN];

  fn_format(full_path, file_name.c_str(), "", "", MY_RETURN_REAL_PATH);

  if (!MySQL_datadir_path.is_ancestor(full_path)) {
    space_by_file[full_path] = tablespace_name;
    file_by_space[tablespace_name] = full_path;
  }
}

/** Remove tablepsace from the list.
@param[in]  tablespace_name tablespace name */
void Tablespace_map::erase(const std::string &tablespace_name) {
  auto i = space_by_file.find(tablespace_name);
  if (i != space_by_file.end()) {
    file_by_space.erase(i->second);
    space_by_file.erase(i);
  }
}

/** Return file name in the backup directory for given tablespace.
@param[in]  file_name source tablespace file name */
std::string Tablespace_map::backup_file_name(const std::string &file_name) const {
  auto i = space_by_file.find(file_name);
  if (i != space_by_file.end()) {
    return ("./" + i->second + ".ibd");
  }

  return (file_name);
}

/** Return original file name for given tablespace.
@param[in]  space_name source tablespace name */
std::string Tablespace_map::external_file_name(
  const std::string &space_name) const {
  auto i = file_by_space.find(space_name);
  if (i != file_by_space.end()) {
    return (i->second);
  }

  return std::string();
}

/** Return the list of external tablespaces. */
Tablespace_map::vector_t Tablespace_map::external_files() const {
  Tablespace_map::vector_t result;
  for (auto i : space_by_file) {
    result.push_back(i.first);
  }
  return (result);
}

/** Serialize talespace list into the current directory. */
bool Tablespace_map::serialize() const {
  using rapidjson::StringBuffer;

  StringBuffer buf;

  bool rc = serialize(buf);
  if (!rc) {
    return (rc);
  }

  const char *path = XBTS_FILE_NAME;
  std::ofstream f(path);

  f.write(buf.GetString(), buf.GetSize());
  f.close();

  return (rc);
}

/** Serialize talespace list into datasink.
@param[in]  ds datasink */
bool Tablespace_map::serialize(ds_ctxt_t *ds) const {
  using rapidjson::StringBuffer;

  StringBuffer buf;

  bool rc = serialize(buf);
  if (!rc) {
    return (rc);
  }

  MY_STAT mystat;
  mystat.st_size = buf.GetSize();
  mystat.st_mtime = my_time(0);

  const char *path = XBTS_FILE_NAME;
  ds_file_t *stream = ds_open(ds, path, &mystat);
  if (stream == NULL) {
    msg("xtrabackup: Error: cannot open output stream for %s\n", path);
    return (false);
  }

  rc = true;

  if (ds_write(stream, buf.GetString(), buf.GetSize())) {
    rc = false;
  }

  if (ds_close(stream)) {
    rc = false;
  }

  return (rc);
}

/** Serialize talespace list into a buffer.
@param[out]  buf output buffer */
bool Tablespace_map::serialize(rapidjson::StringBuffer &buf) const {
  using Writer = rapidjson::Writer<rapidjson::StringBuffer>;

  Writer writer(buf);

  writer.StartObject();
  writer.String("version");
  writer.Int(XBTS_FILE_VERSION);

  writer.String("external_tablespaces");
  writer.StartArray();

  for (auto const& file : space_by_file) {
    writer.StartObject();
    writer.String("file_name");
    writer.String(file.first.c_str(), file.first.length());
    writer.String("tablespace_name");
    writer.String(file.second.c_str(), file.second.length());
    writer.EndObject();
  }
  writer.EndArray();

  writer.EndObject();

  return (true);
}

bool Tablespace_map::deserialize(const std::string &dir) {
  using rapidjson::Document;
  using rapidjson::IStreamWrapper;

  const std::string path = dir + XBTS_FILE_NAME;
  std::ifstream f(path);

  if (f.fail()) {
    msg("xtrabackup: Error: cannot open file '%s'" , path.c_str());
    return (false);
  }

  IStreamWrapper wrapper(f);

  Document doc;
  doc.ParseStream(wrapper);
  if (doc.HasParseError()) {
    msg("xtrabackup: JSON parse error in file '%s'\n", path.c_str());
    return (false);
  }

  auto root = doc.GetObject();

  int version = root["version"].GetInt();
  if (version > XBTS_FILE_VERSION) {
    msg("xtrabackup: Error: wrong '%s' file version %d, maximum version"
        "supported is %d", XBTS_FILE_NAME, version, XBTS_FILE_VERSION);
    return (false);
  }

  auto list = root["external_tablespaces"].GetArray();

  for (auto &entry : list) {
    const auto &object = entry.GetObject();
    add(object["file_name"].GetString(), object["tablespace_name"].GetString());
  }

  return (true);
}
