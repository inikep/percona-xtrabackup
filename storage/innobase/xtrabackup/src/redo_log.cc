/******************************************************
Copyright (c) 2019 Percona LLC and/or its affiliates.

Redo log handling.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA

*******************************************************/

#include "redo_log.h"

#include <dict0dict.h>
#include <log0log.h>
#include <ut0ut.h>
#include <univ.i>

#include <sstream>

#include "backup_copy.h"
#include "backup_mysql.h"
#include "common.h"
#include "os0event.h"
#include "xb0xb.h"
#include "xtrabackup.h"

extern ds_ctxt_t *ds_redo;
/* first block of redo archive file which is all zero in 8.0.22  */
constexpr size_t HEADER_BLOCK_SIZE = 4096;
static bool archive_first_block_zero = false;

Redo_Log_Reader::Redo_Log_Reader() {
  log_hdr_buf.alloc_withkey(UT_NEW_THIS_FILE_PSI_KEY,
                            ut::Count{LOG_FILE_HDR_SIZE});
  log_buf.alloc_withkey(UT_NEW_THIS_FILE_PSI_KEY,
                        ut::Count{redo_log_read_buffer_size});
}

bool Redo_Log_Reader::find_start_checkpoint_lsn() {
  return (true);
}

byte *Redo_Log_Reader::get_header() const { return log_hdr_buf; }

byte *Redo_Log_Reader::get_buffer() const { return log_buf; }

lsn_t Redo_Log_Reader::get_scanned_lsn() const { return (log_scanned_lsn); }

lsn_t Redo_Log_Reader::get_contiguous_lsn() const {
  return ut_uint64_align_down(log_scanned_lsn, OS_FILE_LOG_BLOCK_SIZE);
}

lsn_t Redo_Log_Reader::get_start_checkpoint_lsn() const {
  return (checkpoint_lsn_start);
}

void Redo_Log_Reader::read_log_seg(log_t &log, byte *buf, lsn_t start_lsn,
                                   lsn_t end_lsn) {
}

ssize_t Redo_Log_Reader::read_logfile(bool is_last, bool *finished) {
  log_t &log = *log_sys;

  lsn_t contiguous_lsn =
      ut_uint64_align_down(log_scanned_lsn, OS_FILE_LOG_BLOCK_SIZE);
  lsn_t start_lsn = contiguous_lsn;
  lsn_t scanned_lsn = start_lsn;

  size_t len = 0;

  *finished = false;

  while (!*finished && len <= redo_log_read_buffer_size - RECV_SCAN_SIZE) {
    lsn_t end_lsn = start_lsn + RECV_SCAN_SIZE;

    read_log_seg(log, log_buf + len, start_lsn, end_lsn);

    auto size =
        scan_log_recs(log_buf + len, is_last, start_lsn, &contiguous_lsn,
                      &scanned_lsn, log_scanned_lsn, finished);

    if (size < 0) {
      msg("xtrabackup: Error: read_logfile() failed.\n");
      return (-1);
    }

    start_lsn = end_lsn;
    len += size;
  }

  log_scanned_lsn = scanned_lsn;

  return (len);
}

ssize_t Redo_Log_Reader::scan_log_recs(byte *buf, bool is_last, lsn_t start_lsn,
                                       lsn_t *contiguous_lsn,
                                       lsn_t *read_upto_lsn,
                                       lsn_t checkpoint_lsn, bool *finished) {
  lsn_t scanned_lsn{start_lsn};

  *finished = false;

  *read_upto_lsn = scanned_lsn;

  ssize_t write_size;

  if (!*finished) {
    write_size = RECV_SCAN_SIZE;
  } else {
    write_size =
        ut_uint64_align_up(scanned_lsn, OS_FILE_LOG_BLOCK_SIZE) - start_lsn;
    if (!is_last && scanned_lsn % OS_FILE_LOG_BLOCK_SIZE) {
      write_size -= OS_FILE_LOG_BLOCK_SIZE;
    }
  }

  return (write_size);
}

void Redo_Log_Reader::seek_logfile(lsn_t lsn) { log_scanned_lsn = lsn; }

bool Redo_Log_Parser::parse_log(const byte *buf, size_t len, lsn_t start_lsn) {
  const byte *log_block = buf;
  lsn_t scanned_lsn = start_lsn;
  bool more_data = false;

  do {
    ulint data_len = log_block_get_data_len(log_block);

    if (!recv_sys->parse_start_lsn &&
        log_block_get_first_rec_group(log_block) > 0) {
      /* We found a point from which to start the parsing
      of log records */

      recv_sys->parse_start_lsn =
          scanned_lsn + log_block_get_first_rec_group(log_block);

      msg("Starting to parse redo log at lsn = " LSN_PF "\n",
          recv_sys->parse_start_lsn);

      if (recv_sys->parse_start_lsn < recv_sys->checkpoint_lsn) {
        /* We start to parse log records even before
        checkpoint_lsn, from the beginning of the log
        block which contains the checkpoint_lsn.

        That's because the first group of log records
        in the log block, starts before checkpoint_lsn,
        and checkpoint_lsn could potentially point to
        the middle of some log record. We need to find
        the first group of log records that starts at
        or after checkpoint_lsn. This could be only
        achieved by traversing all groups of log records
        that start within the log block since the first
        one (to discover their beginnings we need to
        parse them). However, we don't want to report
        missing tablespaces for space_id in log records
        before checkpoint_lsn. Hence we need to ignore
        those records and that's why we need a counter
        of bytes to ignore. */

        recv_sys->bytes_to_ignore_before_checkpoint =
            recv_sys->checkpoint_lsn - recv_sys->parse_start_lsn;

        ut_a(recv_sys->bytes_to_ignore_before_checkpoint <=
             OS_FILE_LOG_BLOCK_SIZE - LOG_BLOCK_HDR_SIZE);

        ut_a(recv_sys->checkpoint_lsn % OS_FILE_LOG_BLOCK_SIZE +
                 LOG_BLOCK_TRL_SIZE <
             OS_FILE_LOG_BLOCK_SIZE);

        ut_a(recv_sys->parse_start_lsn % OS_FILE_LOG_BLOCK_SIZE >=
             LOG_BLOCK_HDR_SIZE);
      }

      recv_sys->scanned_lsn = recv_sys->parse_start_lsn;
      recv_sys->recovered_lsn = recv_sys->parse_start_lsn;
    }

    scanned_lsn += data_len;

    if (scanned_lsn > recv_sys->scanned_lsn) {
      /* We were able to find more log data: add it to the
      parsing buffer if parse_start_lsn is already
      non-zero */

      if (recv_sys->len + 4 * OS_FILE_LOG_BLOCK_SIZE >= recv_sys->buf_len) {
        if (!recv_sys_resize_buf()) {
          recv_sys->found_corrupt_log = true;
        }
      }

      if (!recv_sys->found_corrupt_log) {
        more_data =
            recv_sys_add_to_parsing_buf(log_block, scanned_lsn, data_len);
      }

      recv_sys->scanned_lsn = scanned_lsn;
    }

    if (data_len < OS_FILE_LOG_BLOCK_SIZE) {
      /* Log data for this group ends here */

      break;

    } else {
      log_block += OS_FILE_LOG_BLOCK_SIZE;
    }

  } while (log_block < buf + len);

  if (more_data && !recv_sys->found_corrupt_log) {
    /* Try to parse more log records */

    recv_parse_log_recs();

    if (recv_sys->recovered_offset > recv_sys->buf_len / 4) {
      /* Move parsing buffer data to the buffer start */

      recv_reset_buffer();
    }
  }

  return (true);
}

Redo_Log_Writer::Redo_Log_Writer() {
  scratch_buf.alloc_withkey(UT_NEW_THIS_FILE_PSI_KEY,
                            ut::Count{16 * 1024 * 1024});
}

bool Redo_Log_Writer::create_logfile(const char *name) {
  MY_STAT stat_info;

  memset(&stat_info, 0, sizeof(MY_STAT));
  log_file = ds_open(ds_redo, XB_LOG_FILENAME, &stat_info);

  if (log_file == NULL) {
    msg("xtrabackup: error: failed to open the target stream for '%s'.\n",
        XB_LOG_FILENAME);
    return (false);
  }

  return (true);
}

bool Redo_Log_Writer::write_header(byte *hdr) {
  const auto creator = "xtrabkup ";
  const auto creator_size = sizeof "xtrabkup " - 1;

  memcpy(hdr + LOG_HEADER_CREATOR, creator, creator_size);
  ut_sprintf_timestamp(reinterpret_cast<char *>(hdr) +
                       (LOG_HEADER_CREATOR + creator_size));

  if (ds_write(log_file, hdr, LOG_FILE_HDR_SIZE)) {
    msg("xtrabackup: error: write to logfile failed\n");
    return (false);
  }

  return (true);
}

bool Redo_Log_Writer::close_logfile() {
  if (ds_close(log_file) != 0) {
    msg("xtrabackup: error: failed to close logfile\n");
    return (false);
  }
  return (true);
}

bool Redo_Log_Writer::write_buffer(byte *buf, size_t len) {
  byte *write_buf = buf;

  if (ds_write(log_file, write_buf, len)) {
    msg("xtrabackup: Error: write to logfile failed\n");
    return (false);
  }

  return (true);
}

Archived_Redo_Log_Reader::Archived_Redo_Log_Reader() {
  log_buf.alloc_withkey(UT_NEW_THIS_FILE_PSI_KEY,
                        ut::Count{redo_log_read_buffer_size});
  scratch_buf.alloc_withkey(UT_NEW_THIS_FILE_PSI_KEY,
                            ut::Count{UNIV_PAGE_SIZE_MAX});
}

void Archived_Redo_Log_Reader::set_fd(File fd) { file = fd; }

ssize_t Archived_Redo_Log_Reader::read_logfile(bool *finished) {
  auto read_size =
      ut_uint64_align_down(redo_log_read_buffer_size, OS_FILE_LOG_BLOCK_SIZE);

  auto len = my_read(file, log_buf, read_size, MYF(MY_WME | MY_FULL_IO));
  if (len == MY_FILE_ERROR) {
    return (-1);
  }

  ut_a(len % OS_FILE_LOG_BLOCK_SIZE == 0);

  log_scanned_lsn += len;

  if (len < redo_log_read_buffer_size) {
    *finished = true;
  }

  if (srv_redo_log_encrypt) {
    IORequest req_type(IORequest::READ);
    req_type.get_encryption_info().set(log_sys->m_encryption_metadata);
    Encryption encryption(req_type.encryption_algorithm());
    auto err = encryption.decrypt_log(log_buf, len);
    ut_a(err == DB_SUCCESS);
  }

  for (const byte *log_block = log_buf; log_block < log_buf + len;
       log_block += OS_FILE_LOG_BLOCK_SIZE) {
    ut_a(log_block_checksum_is_ok(log_block));
  }

  return (len);
}

bool Archived_Redo_Log_Reader::seek_logfile(lsn_t lsn) {
  lsn = ut_uint64_align_down(lsn, OS_FILE_LOG_BLOCK_SIZE);
  if (lsn < archive_start_lsn) {
    return (false);
  }

  auto pos = lsn - archive_start_lsn;
  if (archive_first_block_zero) pos += HEADER_BLOCK_SIZE;

  my_seek(file, 0, MY_SEEK_END, MYF(MY_FAE));
  auto file_size = my_tell(file, MYF(MY_FAE));

  if (file_size < pos) {
    my_seek(file, 0, MY_SEEK_END, MYF(MY_FAE));
    file_size = my_tell(file, MYF(MY_FAE));

    return (false);
  }

  my_seek(file, pos, MY_SEEK_SET, MYF(MY_FAE));

  log_scanned_lsn = lsn;

  return (true);
}

void Archived_Redo_Log_Reader::set_start_lsn(lsn_t lsn) {
  ut_a(lsn % OS_FILE_LOG_BLOCK_SIZE == 0);

  archive_start_lsn = lsn;
  log_scanned_lsn = lsn + OS_FILE_LOG_BLOCK_SIZE;
}

byte *Archived_Redo_Log_Reader::get_buffer() const { return (log_buf); }

lsn_t Archived_Redo_Log_Reader::get_contiguous_lsn() const {
  return (log_scanned_lsn);
}

Archived_Redo_Log_Monitor::Archived_Redo_Log_Monitor() {
  event = os_event_create();
}

Archived_Redo_Log_Monitor::~Archived_Redo_Log_Monitor() {}

void Archived_Redo_Log_Monitor::close() { os_event_destroy(event); }

void Archived_Redo_Log_Monitor::start() {
  thread = os_thread_create(PFS_NOT_INSTRUMENTED, 0, [this] { thread_func(); });
  thread.start();
  os_event_wait_time_low(event, std::chrono::milliseconds{100}, 0);
  debug_sync_point("stop_before_redo_archive");
}

void Archived_Redo_Log_Monitor::stop() {
  stopped = true;
  os_event_set(event);
  thread.join();
}

Archived_Redo_Log_Reader &Archived_Redo_Log_Monitor::get_reader() {
  return reader;
}

bool Archived_Redo_Log_Monitor::is_ready() const { return ready; }

uint32_t Archived_Redo_Log_Monitor::get_first_log_block_no() const {
  return first_log_block_no;
}

uint32_t Archived_Redo_Log_Monitor::get_first_log_block_checksum() const {
  return first_log_block_checksum;
}

void Archived_Redo_Log_Monitor::skip_for_block(lsn_t lsn, uint32_t no,
                                               uint32_t checksum) {
  bool finished = false;
  lsn_t bytes_read = OS_FILE_LOG_BLOCK_SIZE;

  while (true) {
    auto len = reader.read_logfile(&finished);
    for (auto ptr = reader.get_buffer(); ptr < reader.get_buffer() + len;
         ptr += OS_FILE_LOG_BLOCK_SIZE, bytes_read += OS_FILE_LOG_BLOCK_SIZE) {
      auto arch_block_no = log_block_get_hdr_no(ptr);
      auto arch_block_checksum = log_block_get_checksum(ptr);
      if (no == arch_block_no && checksum == arch_block_checksum) {
        msg("xtrabackup: Archived redo log has caught up\n");
        reader.set_start_lsn(lsn - bytes_read);
        return;
      }
    }
    if (finished) {
      msg_ts(
          "xtrabackup: Finished reading archive, did not find a matching "
          "block\n");
      return;
    }
  }
}

void Archived_Redo_Log_Monitor::parse_archive_dirs(const std::string &s) {
  std::stringstream ss(s);
  std::string item;

  while (std::getline(ss, item, ';')) {
    const auto p = item.find(':');
    if (p != std::string::npos) {
      auto label = item.substr(0, p);
      auto dir = item.substr(p + 1);
      archived_dirs.emplace(label, dir);
    }
  }
}

void Archived_Redo_Log_Monitor::thread_func() {
  my_thread_init();

  stopped = false;
  ready = false;

  auto mysql = xb_mysql_connect();
  if (mysql == nullptr) {
    my_thread_end();
    return;
  }

  char *redo_log_archive_dirs = nullptr;
  char *server_uuid = nullptr;

  mysql_variable vars[] = {
      {"innodb_redo_log_archive_dirs", &redo_log_archive_dirs},
      {"server_uuid", &server_uuid},
      {nullptr, nullptr}};

  struct {
    std::string filename;
    std::string label;
    std::string dir;
    std::string subdir;
  } archive;

  read_mysql_variables(mysql, "SHOW VARIABLES", vars, true);

  if (redo_log_archive_dirs == nullptr || *redo_log_archive_dirs == 0) {
    msg("xtrabackup: Redo Log Archiving is not set up.\n");
    free_mysql_variables(vars);
    mysql_close(mysql);
    my_thread_end();
    return;
  }

  parse_archive_dirs(redo_log_archive_dirs);

  if (archived_dirs.empty()) {
    msg("xtrabackup: Redo Log Archiving is not set up.\n");
    free_mysql_variables(vars);
    mysql_close(mysql);
    my_thread_end();
    return;
  }

  for (const auto &dir : archived_dirs) {
    /* try to create a directory */
    using namespace std::chrono;
    archive.subdir = std::to_string(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch())
            .count());

    archive.dir = dir.second;
    archive.dir.push_back(OS_PATH_SEPARATOR);
    archive.dir.append(archive.subdir);

    if (mkdirp(archive.dir.c_str(), 0750, MYF(MY_WME)) != 0) {
      continue;
    }

    archive.filename = archive.dir;
    archive.filename.push_back(OS_PATH_SEPARATOR);
    archive.filename.append("archive.");
    archive.filename.append(server_uuid);
    archive.filename.append(".000001.log");

    archive.label = dir.first;

    break;
  }

  free_mysql_variables(vars);

  std::string start_query("select innodb_redo_log_archive_start(");

  start_query.append("'");
  start_query.append(archive.label);
  start_query.append("', '");
  start_query.append(archive.subdir);
  start_query.append("')");

  auto res = xb_mysql_query(mysql, start_query.c_str(), true, false);

  if (res == nullptr) {
    msg("xtrabackup: Redo Log Archiving is not used.\n");
    mysql_close(mysql);
    my_thread_end();
    return;
  }

  mysql_free_result(res);

  msg("xtrabackup: Waiting for archive file '%s'\n", archive.filename.c_str());

  /* wait for archive file to appear */
  while (!stopped) {
    bool exists;
    os_file_type_t type;
    if (!os_file_status(archive.filename.c_str(), &exists, &type)) {
      msg("xtrabackup: cannot stat file '%s'\n", archive.filename.c_str());
      break;
    }
    if (exists) {
      break;
    }
    os_event_wait_time_low(event, std::chrono::milliseconds{100}, 0);
    os_event_reset(event);
  }

  File file{-1};
  if (!stopped) {
    file = my_open(archive.filename.c_str(), O_RDONLY, MYF(MY_WME));
    if (file < 0) {
      msg("xtrabackup: error: cannot open '%s'\n", archive.filename.c_str());
      mysql_close(mysql);
      my_thread_end();
      return;
    }

    ut::aligned_array_pointer<byte, UNIV_PAGE_SIZE_MAX> buf;
    buf.alloc_withkey(UT_NEW_THIS_FILE_PSI_KEY,
                      ut::Count{OS_FILE_LOG_BLOCK_SIZE});

    size_t hdr_len = OS_FILE_LOG_BLOCK_SIZE;
    while (hdr_len > 0 && !stopped) {
      size_t n_read = my_read(file, buf, hdr_len, MYF(MY_WME));
      if (n_read == MY_FILE_ERROR) {
        msg("xtrabackup: cannot read from '%s'\n", archive.filename.c_str());
        mysql_close(mysql);
        my_thread_end();
        return;
      }
      os_event_wait_time_low(event, std::chrono::milliseconds{100}, 0);
      os_event_reset(event);
      hdr_len -= n_read;
    }

    /* from 8.0.22 onwards, the first block of redo archive file is all zeros */
    if (log_block_get_checksum(buf) == 0) {
      archive_first_block_zero = true;
      hdr_len = HEADER_BLOCK_SIZE - OS_FILE_LOG_BLOCK_SIZE;
      ut::aligned_array_pointer<byte, UNIV_PAGE_SIZE_MAX> buf2;
      buf2.alloc_withkey(UT_NEW_THIS_FILE_PSI_KEY,
                         ut::Count{HEADER_BLOCK_SIZE - OS_FILE_LOG_BLOCK_SIZE});
      /* Read remaining header of length (4096 - 512) bytes */
      while (hdr_len > 0 && !stopped) {
        size_t n_read = my_read(file, buf2, hdr_len, MYF(MY_WME));
        if (n_read == MY_FILE_ERROR) {
          msg("xtrabackup: cannot read from '%s'\n", archive.filename.c_str());
          mysql_close(mysql);
          my_thread_end();
          return;
        }
        os_event_wait_time_low(event, std::chrono::milliseconds{100}, 0);
        os_event_reset(event);
        hdr_len -= n_read;
      }

      hdr_len = OS_FILE_LOG_BLOCK_SIZE;
      /* Read the actual data in the archive file */
      while (hdr_len > 0 && !stopped) {
        size_t n_read = my_read(file, buf, hdr_len, MYF(MY_WME));
        if (n_read == MY_FILE_ERROR) {
          msg("xtrabackup: cannot read from '%s'\n", archive.filename.c_str());
          mysql_close(mysql);
          my_thread_end();
          return;
        }
        os_event_wait_time_low(event, std::chrono::milliseconds{100}, 0);
        os_event_reset(event);
        hdr_len -= n_read;
      }
      if (srv_redo_log_encrypt) {
        IORequest req_type(IORequest::READ);
        req_type.get_encryption_info().set(log_sys->m_encryption_metadata);
        Encryption encryption(req_type.encryption_algorithm());
        auto err = encryption.decrypt_log(buf, hdr_len);
        ut_a(err == DB_SUCCESS);
      }
    }

    first_log_block_no = log_block_get_hdr_no(buf);
    first_log_block_checksum = log_block_get_checksum(buf);
    ready = true;
  }

  if (ready && !stopped) {
    msg("xtrabackup: Redo Log Archive '%s' found. First log block is "
        "%lu, checksum is %lu.\n",
        archive.filename.c_str(), static_cast<ulong>(first_log_block_no),
        static_cast<ulong>(first_log_block_checksum));
    reader.set_fd(file);
  }

  while (!stopped) {
    os_event_wait_time_low(event, std::chrono::milliseconds{100}, 0);
    os_event_reset(event);
  }

  xb_mysql_query(mysql, "SELECT innodb_redo_log_archive_stop()", false);
  unlink(archive.filename.c_str());
  rmdir(archive.dir.c_str());
  mysql_close(mysql);
  my_thread_end();
}

static dberr_t open_or_create_log_file(bool *log_file_created, ulint i,
                                       fil_space_t **log_space) {
  bool ret;
  os_offset_t size;
  char name[10000];
  ulint dirnamelen;

  *log_file_created = false;

  Fil_path::normalize(srv_log_group_home_dir);

  dirnamelen = strlen(srv_log_group_home_dir);
  ut_a(dirnamelen < (sizeof name) - 10 - sizeof "ib_logfile");
  memcpy(name, srv_log_group_home_dir, dirnamelen);

  /* Add a path separator if needed. */
  if (dirnamelen && name[dirnamelen - 1] != OS_PATH_SEPARATOR) {
    name[dirnamelen++] = OS_PATH_SEPARATOR;
  }

  sprintf(name + dirnamelen, "%s%ld", "ib_logfile", i);

  pfs_os_file_t file = os_file_create(0, name, OS_FILE_OPEN, OS_FILE_NORMAL,
                                      OS_LOG_FILE, true, &ret);
  if (!ret) {
    msg("xtrabackup: error in opening %s\n", name);

    return (DB_ERROR);
  }

  size = os_file_get_size(file);

  if (size != srv_log_file_size) {
    msg("xtrabackup: Error: log file %s is of different size " UINT64PF
        " bytes than specified in the .cnf file %llu bytes!\n",
        name, size, srv_log_file_size * UNIV_PAGE_SIZE);

    return (DB_ERROR);
  }

  ret = os_file_close(file);
  ut_a(ret);

  ut_a(*log_space != NULL);
  ut_ad(fil_validate());

  ut_a(fil_node_create(name, srv_log_file_size / univ_page_size.physical(),
                       *log_space, false, false) != NULL);

  return (DB_SUCCESS);
}

bool Redo_Log_Data_Manager::init() {
  error = true;
  event = os_event_create();

  thread = os_thread_create(PFS_NOT_INSTRUMENTED, 0, [this] { copy_func(); });

  lsn_t flushed_lsn = LOG_START_LSN + LOG_BLOCK_HDR_SIZE;

  if (log_sys_init(false, flushed_lsn, flushed_lsn) != DB_SUCCESS) {
    return (false);
  }

  recv_sys_create();
  recv_sys_init();

  ut_a(srv_log_n_files > 0);

  bool log_file_created = false;
  bool log_created = false;
  bool log_opened = false;
  fil_space_t *log_space = nullptr;

  for (ulong i = 0; i < srv_log_n_files; i++) {
    dberr_t err = open_or_create_log_file(&log_file_created, i, &log_space);
    if (err != DB_SUCCESS) {
      return (false);
    }

    if (log_file_created) {
      log_created = true;
    } else {
      log_opened = true;
    }
    if ((log_opened && log_created)) {
      msg("xtrabackup: Error: all log files must be created at the same time.\n"
          "xtrabackup: All log files must be created also in database "
          "creation.\n"
          "xtrabackup: If you want bigger or smaller log files, shut down the\n"
          "xtrabackup: database and make sure there were no errors in "
          "shutdown.\n"
          "xtrabackup: Then delete the existing log files. Edit the .cnf file\n"
          "xtrabackup: and start the database again.\n");

      return (false);
    }
  }

  /* log_file_created must not be true, if online */
  if (log_file_created) {
    msg("xtrabackup: Something wrong with source files...\n");
    exit(EXIT_FAILURE);
  }

  ut_a(log_space != nullptr);

  archived_log_state = ARCHIVED_LOG_NONE;
  archived_log_monitor.start();

  error = false;

  return (true);
}

bool Redo_Log_Data_Manager::start() {
  error = true;

  if (!reader.find_start_checkpoint_lsn()) {
    return (false);
  }

  if (!writer.create_logfile(XB_LOG_FILENAME)) {
    return (false);
  }

  if (!writer.write_header(reader.get_header())) {
    return (false);
  }

  start_checkpoint_lsn = reader.get_start_checkpoint_lsn();
  last_checkpoint_lsn = start_checkpoint_lsn;
  stop_lsn = 0;

  if (opt_lock_ddl_per_table) {
    mdl_lock_tables();
  }

  bool finished = false;
  while (!finished) {
    if (!copy_once(false, &finished)) {
      return (false);
    }
  }

  /*
   * From this point forward, recv_parse_or_apply_log_rec_body should fail if
   * MLOG_INDEX_LOAD event is parsed as its not safe to continue the backup
   * in any situation (with or without --lock-ddl-per-table).
   */
  mdl_taken = true;

  debug_sync_point("xtrabackup_pause_after_redo_catchup");

  thread.start();

  error = false;

  return (true);
}

void Redo_Log_Data_Manager::track_archived_log(lsn_t start_lsn, const byte *buf,
                                               size_t len) {
  if (!archived_log_monitor.is_ready() ||
      archived_log_state == ARCHIVED_LOG_MATCHED) {
    return;
  }

  if (archived_log_state == ARCHIVED_LOG_NONE) {
    auto no = log_block_get_hdr_no(buf);
    auto checksum = log_block_get_checksum(buf);
    if (no > archived_log_monitor.get_first_log_block_no()) {
      archived_log_monitor.skip_for_block(start_lsn, no, checksum);
      archived_log_state = ARCHIVED_LOG_MATCHED;
    }
  }

  if (archived_log_state == ARCHIVED_LOG_NONE) {
    for (auto ptr = buf; ptr < buf + len;
         ptr += OS_FILE_LOG_BLOCK_SIZE, start_lsn += OS_FILE_LOG_BLOCK_SIZE) {
      auto no = log_block_get_hdr_no(ptr);
      auto checksum = log_block_get_checksum(ptr);
      if (no == archived_log_monitor.get_first_log_block_no() &&
          checksum == archived_log_monitor.get_first_log_block_checksum()) {
        msg("xtrabackup: Switched to archived redo log starting with "
            "LSN: " LSN_PF "\n",
            start_lsn);
        archived_log_monitor.get_reader().set_start_lsn(start_lsn);
        archived_log_state = ARCHIVED_LOG_MATCHED;
      }
    }
  }

  if (archived_log_state == ARCHIVED_LOG_MATCHED) {
    if (archived_log_monitor.get_reader().seek_logfile(
            reader.get_contiguous_lsn())) {
      archived_log_state = ARCHIVED_LOG_POSITIONED;
    }
  }
}

bool Redo_Log_Data_Manager::copy_once(bool is_last, bool *finished) {
  auto start_lsn = reader.get_contiguous_lsn();

  if (archived_log_state == ARCHIVED_LOG_POSITIONED) {
    auto &archive_reader = archived_log_monitor.get_reader();

    if (archive_reader.seek_logfile(start_lsn)) {
      auto len = archive_reader.read_logfile(finished);

      if (len < 0) {
        return (false);
      }

      if (len > 0) {
        if (!parser.parse_log(archive_reader.get_buffer(), len, start_lsn)) {
          return (false);
        }

        if (!writer.write_buffer(archive_reader.get_buffer(), len)) {
          return (false);
        }

        reader.seek_logfile(archive_reader.get_contiguous_lsn());

        return (true);
      }

      if (stop_lsn == 0 || archive_reader.get_contiguous_lsn() >= stop_lsn) {
        return (true);
      }
    }
  }

  auto len = reader.read_logfile(is_last, finished);
  if (len <= 0) {
    return (len == 0);
  }

  track_archived_log(start_lsn, reader.get_buffer(), len);

  if (!parser.parse_log(reader.get_buffer(), len, start_lsn)) {
    return (false);
  }

  if (!writer.write_buffer(reader.get_buffer(), len)) {
    return (false);
  }

  return (true);
}

void Redo_Log_Data_Manager::copy_func() {
  my_thread_init();

  aborted = false;

  bool finished;
  while (!aborted && (stop_lsn == 0 || stop_lsn > reader.get_scanned_lsn())) {
    xtrabackup_io_throttling();

    if (!copy_once(false, &finished)) {
      error = true;
      return;
    }

    if (finished) {
      msg_ts(">> log scanned up to (" LSN_PF ")\n", reader.get_scanned_lsn());

      debug_sync_point("xtrabackup_copy_logfile_pause");

      os_event_reset(event);
      os_event_wait_time_low(event, std::chrono::milliseconds{copy_interval},
                             0);
    }
  }

  if (!aborted && !copy_once(true, &finished)) {
    error = true;
  }

  my_thread_end();
}

lsn_t Redo_Log_Data_Manager::get_last_checkpoint_lsn() const {
  return (last_checkpoint_lsn);
}

lsn_t Redo_Log_Data_Manager::get_stop_lsn() const { return (stop_lsn); }

lsn_t Redo_Log_Data_Manager::get_start_checkpoint_lsn() const {
  return (start_checkpoint_lsn);
}

lsn_t Redo_Log_Data_Manager::get_scanned_lsn() const { return (scanned_lsn); }

void Redo_Log_Data_Manager::set_copy_interval(ulint interval) {
  copy_interval = interval;
}

void Redo_Log_Data_Manager::abort() {
  aborted = true;
  os_event_set(event);
  thread.join();
  archived_log_monitor.stop();
}

bool Redo_Log_Data_Manager::is_error() const { return (error); }

Redo_Log_Data_Manager::~Redo_Log_Data_Manager() { os_event_destroy(event); }

bool Redo_Log_Data_Manager::stop_at(lsn_t lsn, lsn_t checkpoint_lsn) {
  last_checkpoint_lsn = checkpoint_lsn;
  msg("xtrabackup: The latest check point (for incremental): '" LSN_PF "'\n",
      last_checkpoint_lsn);
  msg("xtrabackup: Stopping log copying thread at LSN " LSN_PF ".\n", lsn);

  stop_lsn = lsn;
  os_event_set(event);
  thread.join();

  archived_log_monitor.stop();

  scanned_lsn = reader.get_scanned_lsn();

  if (last_checkpoint_lsn > scanned_lsn) {
    msg("xtrabackup: error: last checkpoint LSN (" LSN_PF
        ") is larger than last copied LSN (" LSN_PF ").\n",
        last_checkpoint_lsn, scanned_lsn);
    return (false);
  }

  if (!writer.close_logfile()) {
    return (false);
  }

  return (true);
}

void Redo_Log_Data_Manager::close() {
  log_sys_close();
  archived_log_monitor.close();
  os_event_destroy(event);
}
