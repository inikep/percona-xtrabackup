########################################################################
# Bug #1343722: Too easy to backup wrong datadir with multiple instances
########################################################################

start_server_with_id 1

socket=$MYSQLD_SOCKET

start_server_with_id 2

# Try to backup server 2, but use server 1's connection socket
xtrabackup --backup --socket=$socket --target-dir=$topdir/backup 2>&1 | tee $topdir/pxb1343722.log

run_cmd grep 'has different values' $topdir/pxb1343722.log

