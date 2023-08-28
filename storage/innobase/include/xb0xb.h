/******************************************************
Copyright (c) 2012 Percona LLC and/or its affiliates.

Declarations of XtraBackup functions called by InnoDB code.

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

#ifndef xb0xb_h
#define xb0xb_h

extern bool innodb_log_checksums_specified;
extern bool innodb_checksum_algorithm_specified;

extern bool opt_lock_ddl_per_table;

extern bool use_dumped_tablespace_keys;

/******************************************************************************
Callback used in buf_page_io_complete() to detect compacted pages.
@return TRUE if the page is marked as compacted, FALSE otherwise. */
ibool
buf_page_is_compacted(
/*==================*/
	const byte*	page);	/*!< in: a database page */

/******************************************************************************
Rebuild all secondary indexes in all tables in separate spaces. Called from
innobase_start_or_create_for_mysql(). */
void
xb_compact_rebuild_indexes(void);

/** Fetch tablespace key from "xtrabackup_keys".
@param[in]	space_id	tablespace id
@param[out]	key		fetched tablespace key
@param[out]	key		fetched tablespace iv */
void
xb_fetch_tablespace_key(ulint space_id, byte *key, byte *iv);

/** Add file to tablespace map.
@param[in]	file_name	file name
@param[in]	tablespace_name	corresponding tablespace name */
void
xb_tablespace_map_add(const char *file_name, const char *tablespace_name);

/** Delete tablespace from mapping.
@param[in]	tablespace_name	tablespace name */
void
xb_tablespace_map_delete(const char *tablespace_name);

/** Lookup backup file name for given file.
@param[in]	file_name	file name
@return		local file name */
std::string
xb_tablespace_backup_file_path(const std::string &file_name);

#endif
