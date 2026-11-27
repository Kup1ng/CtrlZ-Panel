# River indexes (invalid `*_ccnew` leftovers)

River's own reindexer is off in the worker (`internal/worker/batchjobs`, `ReindexerSchedule`): it runs `REINDEX CONCURRENTLY`, which the worker's role timeouts and the watchdog cut short, and a cut build leaves an invalid index named `*_ccnew` behind. The River tables are small, so nothing needs reindexing on a schedule.

An install that ran an earlier build keeps the invalid indexes it left. They are harmless to reads and add a little write cost. Drop them once after the upgrade, as the `postgres` OS user over the socket in the postgres container:

```sh
docker compose exec -T postgres gosu postgres psql -U postgres -d ctrlz -X -At <<'SQL'
SELECT format('DROP INDEX CONCURRENTLY river.%I', c.relname)
FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'river' AND NOT i.indisvalid AND c.relname LIKE '%ccnew%'
\gexec
SQL
```

`\gexec` runs each statement it gets on its own, outside a transaction, as `DROP INDEX CONCURRENTLY` needs (a `-c` string would not take the backslash command). The database name is `ctrlz` unless the install changed `CTRLZ_DB_NAME`. A valid index is never named by the query, so running it twice is safe.

If a reindex is wanted later (the tables grew), run `REINDEX TABLE CONCURRENTLY river.<table>` as the migrator in a quiet hour, outside the worker's timeouts, then run the query above again.
